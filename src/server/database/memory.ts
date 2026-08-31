/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * In-memory database. The default backend, and the one the test suite runs
 * against, so behavior is identical whether or not Postgres is configured.
 *
 * It is explicit about what it is: `healthy()` is true, but nothing survives a
 * restart, and the resolver says so in /api/health.
 */

import { auditLogsStore, verifyAuditChain } from "../core/store";
import type { AuditLogEntry } from "../core/store";
import type { AgentRunRecord } from "../agents/types";
import type { Finding } from "../findings/types";
import type {
  AgentRunRepository,
  AuditRepository,
  Database,
  FindingQuery,
  FindingRepository,
} from "./types";

class MemoryFindingRepository implements FindingRepository {
  private rows: Finding[] = [];

  async insertMany(findings: Finding[]): Promise<void> {
    for (const f of findings) this.rows.unshift(f);
    while (this.rows.length > 1000) this.rows.pop();
  }

  async get(id: string): Promise<Finding | undefined> {
    return this.rows.find((f) => f.id === id);
  }

  async list(q: FindingQuery): Promise<Finding[]> {
    const out = this.rows.filter(
      (f) =>
        (!q.projectId || f.projectId === q.projectId) &&
        (!q.traceId || f.traceId === q.traceId) &&
        (!q.status || f.validation.status === q.status),
    );
    return q.limit ? out.slice(0, q.limit) : out;
  }

  async updateValidation(id: string, validation: Finding["validation"]): Promise<Finding | undefined> {
    const f = this.rows.find((x) => x.id === id);
    if (!f) return undefined;
    f.validation = validation;
    f.updatedAt = new Date().toISOString();
    return f;
  }
}

class MemoryAuditRepository implements AuditRepository {
  // Backed by the existing process-wide store so the synchronous
  // addAuditLog() call sites keep working unchanged.
  async append(_entry: AuditLogEntry): Promise<void> {
    /* addAuditLog already pushed it; nothing further to persist. */
  }

  async list(limit = 200): Promise<AuditLogEntry[]> {
    return auditLogsStore.slice(0, limit);
  }

  async verifyChain(): Promise<{ intact: boolean; brokenAt?: string; checked: number }> {
    return verifyAuditChain();
  }
}

class MemoryAgentRunRepository implements AgentRunRepository {
  private rows: AgentRunRecord[] = [];

  async upsert(run: AgentRunRecord): Promise<void> {
    const i = this.rows.findIndex((r) => r.runId === run.runId);
    if (i >= 0) this.rows[i] = run;
    else this.rows.unshift(run);
    while (this.rows.length > 500) this.rows.pop();
  }

  async list(limit = 200): Promise<AgentRunRecord[]> {
    return this.rows.slice(0, limit);
  }
}

export class MemoryDatabase implements Database {
  readonly kind = "memory" as const;
  findings = new MemoryFindingRepository();
  audit = new MemoryAuditRepository();
  agentRuns = new MemoryAgentRunRepository();

  async healthy(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {
    /* nothing to close */
  }
}
