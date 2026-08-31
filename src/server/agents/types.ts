/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Agent contract (§5). Every agent publishes a descriptor so the Agent Manager
 * can enforce permissions, tool allowlists, risk and timeouts without the
 * orchestrator hard-coding any agent.
 */

import type { ZodTypeAny } from "zod";
import type { RiskLevel } from "../tools/types";
import type { AgentResult } from "./base";

export type AgentLifecycleState =
  | "IDLE"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "TIMEOUT"
  | "CANCELLED";

export interface AgentMemoryPolicy {
  /** How many past tasks the agent retains in working memory. */
  maxTasks: number;
  /** Never persist raw tool output into general-purpose memory (§23). */
  persistRawOutput: boolean;
}

export interface AgentDescriptor {
  id: string;
  name: string;
  description: string;
  capabilities: string[];
  /** Skill ids this agent may select. */
  skills: string[];
  /** Tool ids this agent may request. Enforced by the Agent Manager. */
  allowedTools: string[];
  /** Coarse permissions, e.g. ["tool:execute", "scope:read"]. */
  permissions: string[];
  riskLevel: RiskLevel;
  timeoutMs: number;
  inputSchema: ZodTypeAny;
  outputSchema: ZodTypeAny;
  memoryPolicy: AgentMemoryPolicy;
}

/** Minimal surface the Agent Manager needs to dispatch to an agent. */
export interface RunnableAgent {
  readonly id: string;
  describe(): AgentDescriptor;
  run(input: unknown, ctx?: AgentRunContext): Promise<AgentResult<unknown>>;
}

export interface AgentRunContext {
  traceId: string;
  projectId: string;
  /** Aborted when the run times out or is cancelled. */
  signal?: AbortSignal;
}

export interface AgentRunRecord {
  runId: string;
  agentId: string;
  traceId: string;
  projectId: string;
  state: AgentLifecycleState;
  startedAt: string;
  finishedAt?: string;
  durationMs?: number;
  error?: string;
}
