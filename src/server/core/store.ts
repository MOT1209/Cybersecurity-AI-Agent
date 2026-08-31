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

import { createHash } from "crypto";

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
}

// Audit Trail Logs Store
export const auditLogsStore: AuditLogEntry[] = [];

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
): AuditLogEntry {
  const log: AuditLogEntry = {
    id: `log_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    traceId: `trace_${Date.now()}`,
    timestamp: new Date().toISOString(),
    actor,
    action,
    target,
    status,
    details,
    ipAddress: "127.0.0.1 (Sandbox)",
  };
  if (typeof rawOutput === "string") {
    log.outputHash = `sha256:${createHash("sha256").update(rawOutput).digest("hex")}`;
  }
  auditLogsStore.unshift(log);
  if (auditLogsStore.length > 200) auditLogsStore.pop();
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
