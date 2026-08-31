/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * In-memory application state + audit trail. Extracted from server.ts (Phase 0).
 *
 * The exported arrays/objects are the single source of truth and are mutated by
 * reference (unshift/pop) across the app, exactly as before the extraction. A
 * later phase replaces these with a real database (Drizzle/Postgres).
 */

import { createHash, randomUUID } from "crypto";

// In-Memory Project & Scope State
export const projectsStore = [
  {
    id: "proj_alpha_lab",
    name: "Authorized Enterprise Staging Lab",
    targetDomain: "target-corp.lab",
    targetIps: ["192.168.1.50", "192.168.1.51", "10.0.0.12", "127.0.0.1", "localhost"],
    inScope: ["192.168.1.50", "192.168.1.51", "*.target-corp.lab", "http://192.168.1.50:8080/api/v1/*"],
    outOfScope: ["192.168.1.1", "production-billing.target-corp.com", "8.8.8.8"],
    allowedTools: ["nmap", "nuclei", "subfinder", "semgrep", "trivy", "zap", "prowler", "volatility"],
    policy: {
      strictSandbox: true,
      requireApprovalForHighRisk: true,
    },
  },
];

export interface AuditLogEntry {
  id: string;
  traceId: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  status: string;
  details: string;
  ipAddress: string;
  /** sha256 of raw tool output, when applicable — enables report traceability. */
  outputHash?: string;
  /** Hash of the previous entry, or null for the first. */
  prevHash: string | null;
  /** sha256 over this entry's fields plus prevHash — the chain link. */
  entryHash: string;
}

// Audit Trail Logs Store
export const auditLogsStore: AuditLogEntry[] = [];

/**
 * Head of the audit hash chain. Each entry commits to its predecessor, so
 * removing or editing any record breaks verification for everything after it.
 * This is tamper-EVIDENCE, not tamper-proofing: an attacker with write access
 * to the whole store could recompute the chain. It raises the cost of a quiet
 * edit from trivial to total.
 */
let auditChainHead: string | null = null;

/**
 * Durable sinks for audit entries. Registered by the database layer rather than
 * imported here, so core/store stays free of a persistence dependency (and of
 * the import cycle that would come with it).
 */
type AuditSink = (entry: AuditLogEntry) => Promise<void> | void;
const auditSinks: AuditSink[] = [];

export function registerAuditSink(sink: AuditSink): () => void {
  auditSinks.push(sink);
  return () => {
    const i = auditSinks.indexOf(sink);
    if (i >= 0) auditSinks.splice(i, 1);
  };
}

/** Canonical serialization for hashing — field order is fixed on purpose. */
function auditDigest(e: Omit<AuditLogEntry, "entryHash">): string {
  const canonical = [
    e.id, e.traceId, e.timestamp, e.actor, e.action,
    e.target, e.status, e.details, e.ipAddress,
    e.outputHash ?? "", e.prevHash ?? "",
  ].join("\u0000");
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * Recompute the chain over the retained entries and report the first broken
 * link. Entries are stored newest-first, so verification walks them in reverse.
 */
export function verifyAuditChain(): { intact: boolean; brokenAt?: string; checked: number } {
  const chronological = [...auditLogsStore].reverse();
  let expectedPrev: string | null = chronological.length
    ? chronological[0].prevHash
    : null;
  for (const entry of chronological) {
    if (entry.prevHash !== expectedPrev) {
      return { intact: false, brokenAt: entry.id, checked: chronological.length };
    }
    const { entryHash, ...rest } = entry;
    if (auditDigest(rest) !== entryHash) {
      return { intact: false, brokenAt: entry.id, checked: chronological.length };
    }
    expectedPrev = entryHash;
  }
  return { intact: true, checked: chronological.length };
}

/**
 * Append an immutable-style audit record (newest first, capped at 200).
 *
 * `rawOutput` is optional and, when provided, is hashed (sha256) rather than
 * stored — so report findings can reference a verifiable output fingerprint
 * without persisting sensitive raw output in the log.
 */
export function addAuditLog(
  actor: string,
  action: string,
  target: string,
  status: string,
  details: string,
  rawOutput?: string,
  traceId?: string,
): AuditLogEntry {
  const draft: Omit<AuditLogEntry, "entryHash"> = {
    // randomUUID rather than Date.now(): two entries in the same millisecond
    // previously collided on both id and traceId.
    id: `log_${randomUUID()}`,
    traceId: traceId ?? `trc_${randomUUID()}`,
    timestamp: new Date().toISOString(),
    actor,
    action,
    target,
    status,
    details,
    ipAddress: "127.0.0.1 (Sandbox)",
    prevHash: auditChainHead,
  };
  if (typeof rawOutput === "string") {
    draft.outputHash = `sha256:${createHash("sha256").update(rawOutput).digest("hex")}`;
  }
  const log: AuditLogEntry = { ...draft, entryHash: auditDigest(draft) };
  auditChainHead = log.entryHash;

  auditLogsStore.unshift(log);
  if (auditLogsStore.length > 200) auditLogsStore.pop();

  // Write-through to the configured backend. Not awaited (addAuditLog is called
  // from synchronous security paths) but never silently dropped.
  for (const sink of auditSinks) {
    try {
      const pending = sink(log);
      if (pending) {
        void pending.catch((err: Error) =>
          console.error(`[audit] Failed to persist entry ${log.id}: ${err.message}`),
        );
      }
    } catch (err) {
      console.error(`[audit] Audit sink threw for ${log.id}: ${(err as Error).message}`);
    }
  }

  return log;
}

// Error Recovery & Circuit Breakers Management
export interface ToolCircuitBreaker {
  consecutiveFailures: number;
  lastFailureTime: number;
  state: "CLOSED" | "HALF_OPEN" | "OPEN";
  cooldownPeriodMs: number;
}

export const circuitBreakers: Record<string, ToolCircuitBreaker> = {
  nmap: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 20000 },
  nuclei: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 30000 },
  semgrep: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 15000 },
  zap: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 30000 },
  trivy: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 20000 },
  prowler: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 25000 },
};

/**
 * Recorded error-recovery diagnoses. Deliberately EMPTY at boot.
 *
 * This store previously shipped with three fabricated incidents — complete with
 * invented timings and "recovered successfully" outcomes — which made a fresh
 * install look like it had already run scans. An empty history is the truth.
 */
export const errorRecoveryEventsStore: any[] = [];
