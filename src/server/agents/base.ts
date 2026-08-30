/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared agent scaffolding: bounded context memory (last 3 tasks), a tool-call
 * log, and an LLM reasoning helper that always degrades to a domain-specific
 * local fallback and wraps untrusted input in the injection boundary.
 */

import { generateJSON, wrapUserInput } from "../llm/index";
import type { ToolRunResult } from "../sandbox/types";

export interface AgentTask {
  id: string;
  input: unknown;
  startedAt: string;
}

export interface ToolCallRecord {
  tool: string;
  target: string;
  status: string;
  exitCode: number;
  mode: string;
  at: string;
}

export interface AgentResult<T> {
  agentId: string;
  summary: string;
  data: T;
  toolCalls: ToolCallRecord[];
  provider: string;
  fallback: boolean;
}

export abstract class BaseAgent {
  abstract readonly id: string;

  private memory: AgentTask[] = [];
  protected toolCalls: ToolCallRecord[] = [];

  /** Record a task in bounded (last 3) context memory. */
  protected remember(input: unknown): AgentTask {
    const task: AgentTask = {
      id: `task_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      input,
      startedAt: new Date().toISOString(),
    };
    this.memory.unshift(task);
    if (this.memory.length > 3) this.memory.pop();
    return task;
  }

  protected recentContext(): AgentTask[] {
    return [...this.memory];
  }

  /** Append a tool execution to this agent's call log. */
  protected logToolCall(result: ToolRunResult): void {
    this.toolCalls.push({
      tool: result.toolId,
      target: result.target,
      status: result.status,
      exitCode: result.exitCode,
      mode: result.sandbox.mode,
      at: result.timestamp,
    });
  }

  /**
   * Ask the model for structured JSON, wrapping untrusted content in the
   * injection boundary and guaranteeing a result via `localFallback`.
   */
  protected async reason<T>(
    untrustedContext: string,
    instruction: string,
    schemaHint: string,
    localFallback: () => T,
  ): Promise<{ data: T; provider: string; fallback: boolean }> {
    const prompt = `${instruction}\n\n${wrapUserInput(untrustedContext)}`;
    const res = await generateJSON<T>(prompt, schemaHint, undefined, localFallback);
    return { data: res.data, provider: res.provider, fallback: res.fallback };
  }
}
