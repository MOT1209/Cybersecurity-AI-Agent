/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Postgres backend. `pg` is imported dynamically so the app still boots when the
 * driver or the server is absent — availability is probed, never assumed.
 *
 * Every statement is parameterized. There is no string-concatenated SQL in this
 * file, and identifiers are never taken from caller input.
 */

import { createHash } from "crypto";
import type { AuditLogEntry } from "../core/store";
import type { AgentRunRecord } from "../agents/types";
import type { Evidence, Finding, Severity, Validation, VerificationStatus } from "../findings/types";
import type {
  AgentRunRepository,
  AuditRepository,
  Database,
  FindingQuery,
  FindingRepository,
} from "./types";

/** Minimal surface we use from `pg`, so the driver stays swappable. */
export interface PgPool {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
  end(): Promise<void>;
}

export async function createPool(connectionString: string): Promise<PgPool> {
  const mod: Record<string, unknown> = await import("pg");
  const pgModule = (mod.default ?? mod) as { Pool: new (cfg: unknown) => PgPool };
  return new pgModule.Pool({
    connectionString,
    max: Number(process.env.DATABASE_POOL_MAX) || 10,
    connectionTimeoutMillis: Number(process.env.DATABASE_CONNECT_TIMEOUT_MS) || 5000,
    // TLS is required unless the operator explicitly opts out for a local dev
    // server; defaulting to plaintext would silently ship credentials in clear.
    ssl:
      String(process.env.DATABASE_SSL || "true").toLowerCase() === "false"
        ? undefined
        : { rejectUnauthorized: String(process.env.DATABASE_SSL_STRICT || "true").toLowerCase() !== "false" },
  });
}

const asStringArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

function rowToFinding(r: Record<string, unknown>, evidence: Evidence[]): Finding {
  const validation: Validation = {
    status: String(r.verification_status) as VerificationStatus,
    confidence: Number(r.confidence ?? 0),
    validatedByAgent: (r.validated_by_agent as string) ?? undefined,
    validatedAt: r.validated_at ? new Date(r.validated_at as string).toISOString() : undefined,
    rationale: (r.validation_rationale as string) ?? undefined,
    falsePositiveIndicators: asStringArray(r.false_positive_indicators),
    missingEvidence: asStringArray(r.missing_evidence),
  };
  return {
    id: String(r.id),
    projectId: String(r.project_id),
    taskId: (r.task_id as string) ?? undefined,
    traceId: (r.trace_id as string) ?? undefined,
    target: String(r.target),
    asset: String(r.asset),
    discoveredByAgent: String(r.discovered_by_agent),
    toolUsed: String(r.tool_used),
    title: String(r.title),
    description: String(r.description),
    evidence,
    severity: String(r.severity) as Severity,
    cvssScore: r.cvss_score == null ? undefined : Number(r.cvss_score),
    cwe: asStringArray(r.cwe),
    owaspCategory: (r.owasp_category as string) ?? undefined,
    impact: String(r.impact),
    validation,
    remediation: (r.remediation as Finding["remediation"]) ?? undefined,
    createdAt: new Date(r.created_at as string).toISOString(),
    updatedAt: new Date(r.updated_at as string).toISOString(),
  };
}

class PgFindingRepository implements FindingRepository {
  constructor(private pool: PgPool) {}

  async insertMany(findings: Finding[]): Promise<void> {
    for (const f of findings) {
      await this.pool.query(
        `INSERT INTO findings (
           id, project_id, task_id, trace_id, target, asset, discovered_by_agent,
           tool_used, title, description, severity, cvss_score, cwe,
           owasp_category, impact, verification_status, confidence,
           validated_by_agent, validated_at, validation_rationale,
           false_positive_indicators, missing_evidence, remediation,
           created_at, updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
         ON CONFLICT (id) DO NOTHING`,
        [
          f.id, f.projectId, f.taskId ?? null, f.traceId ?? null, f.target, f.asset,
          f.discoveredByAgent, f.toolUsed, f.title, f.description, f.severity,
          f.cvssScore ?? null, f.cwe, f.owaspCategory ?? null, f.impact,
          f.validation.status, f.validation.confidence,
          f.validation.validatedByAgent ?? null, f.validation.validatedAt ?? null,
          f.validation.rationale ?? null, f.validation.falsePositiveIndicators,
          f.validation.missingEvidence, f.remediation ? JSON.stringify(f.remediation) : null,
          f.createdAt, f.updatedAt,
        ],
      );
      for (const e of f.evidence) {
        await this.pool.query(
          `INSERT INTO evidence (finding_id, source, observation, output_hash, collected_at)
           VALUES ($1,$2,$3,$4,$5)`,
          [f.id, e.source, e.observation, e.outputHash ?? null, e.collectedAt],
        );
      }
    }
  }

  private async evidenceFor(ids: string[]): Promise<Map<string, Evidence[]>> {
    const map = new Map<string, Evidence[]>();
    if (!ids.length) return map;
    const { rows } = await this.pool.query(
      `SELECT finding_id, source, observation, output_hash, collected_at
         FROM evidence WHERE finding_id = ANY($1) ORDER BY id ASC`,
      [ids],
    );
    for (const r of rows) {
      const key = String(r.finding_id);
      const list = map.get(key) ?? [];
      list.push({
        source: String(r.source),
        observation: String(r.observation),
        outputHash: (r.output_hash as string) ?? undefined,
        collectedAt: new Date(r.collected_at as string).toISOString(),
      });
      map.set(key, list);
    }
    return map;
  }

  async get(id: string): Promise<Finding | undefined> {
    const { rows } = await this.pool.query(`SELECT * FROM findings WHERE id = $1`, [id]);
    if (!rows.length) return undefined;
    const ev = await this.evidenceFor([id]);
    return rowToFinding(rows[0], ev.get(id) ?? []);
  }

  async list(q: FindingQuery): Promise<Finding[]> {
    // Predicates are appended as parameter placeholders only; no interpolation.
    const where: string[] = [];
    const values: unknown[] = [];
    if (q.projectId) { values.push(q.projectId); where.push(`project_id = $${values.length}`); }
    if (q.traceId) { values.push(q.traceId); where.push(`trace_id = $${values.length}`); }
    if (q.status) { values.push(q.status); where.push(`verification_status = $${values.length}`); }
    values.push(Math.min(Math.max(q.limit ?? 200, 1), 1000));

    const { rows } = await this.pool.query(
      `SELECT * FROM findings
        ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
        ORDER BY created_at DESC
        LIMIT $${values.length}`,
      values,
    );
    const ev = await this.evidenceFor(rows.map((r) => String(r.id)));
    return rows.map((r) => rowToFinding(r, ev.get(String(r.id)) ?? []));
  }

  async updateValidation(id: string, v: Validation): Promise<Finding | undefined> {
    await this.pool.query(
      `UPDATE findings SET
         verification_status = $2, confidence = $3, validated_by_agent = $4,
         validated_at = $5, validation_rationale = $6,
         false_positive_indicators = $7, missing_evidence = $8, updated_at = now()
       WHERE id = $1`,
      [
        id, v.status, v.confidence, v.validatedByAgent ?? null,
        v.validatedAt ?? null, v.rationale ?? null,
        v.falsePositiveIndicators, v.missingEvidence,
      ],
    );
    return this.get(id);
  }
}

class PgAuditRepository implements AuditRepository {
  constructor(private pool: PgPool) {}

  async append(e: AuditLogEntry): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_logs (
         id, trace_id, actor, action, target, status, details, ip_address,
         output_hash, prev_hash, entry_hash, created_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (id) DO NOTHING`,
      [
        e.id, e.traceId, e.actor, e.action, e.target, e.status, e.details,
        e.ipAddress, e.outputHash ?? null, e.prevHash, e.entryHash, e.timestamp,
      ],
    );
  }

  async list(limit = 200): Promise<AuditLogEntry[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1`,
      [Math.min(Math.max(limit, 1), 1000)],
    );
    return rows.map((r) => ({
      id: String(r.id),
      traceId: String(r.trace_id),
      timestamp: new Date(r.created_at as string).toISOString(),
      actor: String(r.actor),
      action: String(r.action),
      target: String(r.target),
      status: String(r.status),
      details: String(r.details),
      ipAddress: String(r.ip_address ?? ""),
      outputHash: (r.output_hash as string) ?? undefined,
      prevHash: (r.prev_hash as string) ?? null,
      entryHash: String(r.entry_hash),
    }));
  }

  async verifyChain(): Promise<{ intact: boolean; brokenAt?: string; checked: number }> {
    const { rows } = await this.pool.query(
      `SELECT id, trace_id, actor, action, target, status, details, ip_address,
              output_hash, prev_hash, entry_hash, created_at
         FROM audit_logs ORDER BY created_at ASC`,
    );
    let expectedPrev: string | null = rows.length ? ((rows[0].prev_hash as string) ?? null) : null;
    for (const r of rows) {
      const prev = (r.prev_hash as string) ?? null;
      if (prev !== expectedPrev) {
        return { intact: false, brokenAt: String(r.id), checked: rows.length };
      }
      const canonical = [
        r.id, r.trace_id, new Date(r.created_at as string).toISOString(), r.actor,
        r.action, r.target, r.status, r.details, r.ip_address,
        r.output_hash ?? "", prev ?? "",
      ].join("\u0000");
      if (createHash("sha256").update(canonical).digest("hex") !== r.entry_hash) {
        return { intact: false, brokenAt: String(r.id), checked: rows.length };
      }
      expectedPrev = String(r.entry_hash);
    }
    return { intact: true, checked: rows.length };
  }
}

class PgAgentRunRepository implements AgentRunRepository {
  constructor(private pool: PgPool) {}

  async upsert(r: AgentRunRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO agent_runs (
         run_id, agent_id, project_id, trace_id, state, error,
         started_at, finished_at, duration_ms
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (run_id) DO UPDATE SET
         state = EXCLUDED.state, error = EXCLUDED.error,
         finished_at = EXCLUDED.finished_at, duration_ms = EXCLUDED.duration_ms`,
      [
        r.runId, r.agentId, r.projectId, r.traceId, r.state, r.error ?? null,
        r.startedAt, r.finishedAt ?? null, r.durationMs ?? null,
      ],
    );
  }

  async list(limit = 200): Promise<AgentRunRecord[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM agent_runs ORDER BY started_at DESC LIMIT $1`,
      [Math.min(Math.max(limit, 1), 1000)],
    );
    return rows.map((r) => ({
      runId: String(r.run_id),
      agentId: String(r.agent_id),
      traceId: String(r.trace_id),
      projectId: String(r.project_id),
      state: String(r.state) as AgentRunRecord["state"],
      error: (r.error as string) ?? undefined,
      startedAt: new Date(r.started_at as string).toISOString(),
      finishedAt: r.finished_at ? new Date(r.finished_at as string).toISOString() : undefined,
      durationMs: r.duration_ms == null ? undefined : Number(r.duration_ms),
    }));
  }
}

export class PostgresDatabase implements Database {
  readonly kind = "postgres" as const;
  findings: FindingRepository;
  audit: AuditRepository;
  agentRuns: AgentRunRepository;

  constructor(private pool: PgPool) {
    this.findings = new PgFindingRepository(pool);
    this.audit = new PgAuditRepository(pool);
    this.agentRuns = new PgAgentRunRepository(pool);
  }

  async healthy(): Promise<boolean> {
    try {
      await this.pool.query("SELECT 1");
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
