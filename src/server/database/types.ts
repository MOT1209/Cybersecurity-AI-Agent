/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Persistence contracts. Two implementations exist: an in-memory store (the
 * default, and what the tests run against) and Postgres.
 *
 * The interfaces are async on purpose, so switching backends is a
 * configuration change rather than a rewrite of every call site.
 */

import type { Finding } from "../findings/types";
import type { AuditLogEntry } from "../core/store";
import type { AgentRunRecord } from "../agents/types";

export interface FindingQuery {
  projectId?: string;
  traceId?: string;
  status?: Finding["validation"]["status"];
  limit?: number;
}

export interface FindingRepository {
  insertMany(findings: Finding[]): Promise<void>;
  get(id: string): Promise<Finding | undefined>;
  list(query: FindingQuery): Promise<Finding[]>;
  updateValidation(id: string, validation: Finding["validation"]): Promise<Finding | undefined>;
}

/**
 * Append-only by contract: there is deliberately no update or delete. The audit
 * trail is evidence, and evidence that can be edited is not evidence.
 */
export interface AuditRepository {
  append(entry: AuditLogEntry): Promise<void>;
  list(limit?: number): Promise<AuditLogEntry[]>;
  /** Recompute the hash chain and report the first broken link, if any. */
  verifyChain(): Promise<{ intact: boolean; brokenAt?: string; checked: number }>;
}

export interface AgentRunRepository {
  upsert(run: AgentRunRecord): Promise<void>;
  list(limit?: number): Promise<AgentRunRecord[]>;
}

export interface Database {
  readonly kind: "memory" | "postgres";
  findings: FindingRepository;
  audit: AuditRepository;
  agentRuns: AgentRunRepository;
  /** True when the backend is reachable right now. */
  healthy(): Promise<boolean>;
  close(): Promise<void>;
}
