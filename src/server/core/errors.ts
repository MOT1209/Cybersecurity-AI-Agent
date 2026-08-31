/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Typed, machine-readable failure modes for the tool/agent runtime.
 *
 * These exist to satisfy the platform's honest-failure contract: when a tool
 * cannot really run, the caller receives an explicit NOT_AVAILABLE with the
 * actual reason — never a fabricated success.
 */

/** A tool id that is not present in the tool registry was requested. */
export class ToolNotRegisteredError extends Error {
  readonly code = "TOOL_NOT_REGISTERED" as const;
  constructor(public readonly toolId: string) {
    super(`Tool "${toolId}" is not registered. Unknown tools are denied by default.`);
    this.name = "ToolNotRegisteredError";
  }
}

/**
 * The tool is registered but cannot be executed for real right now — no
 * implemented adapter, or no working sandbox executor. Map to HTTP 503.
 */
export class ToolNotAvailableError extends Error {
  readonly code = "NOT_AVAILABLE" as const;
  constructor(
    public readonly toolId: string,
    public readonly detail: string,
  ) {
    super(`NOT_AVAILABLE: tool "${toolId}" cannot be executed — ${detail}`);
    this.name = "ToolNotAvailableError";
  }
}

/** An agent id that is not present in the agent registry was dispatched to. */
export class AgentNotRegisteredError extends Error {
  readonly code = "AGENT_NOT_REGISTERED" as const;
  constructor(public readonly agentId: string) {
    super(`Agent "${agentId}" is not registered.`);
    this.name = "AgentNotRegisteredError";
  }
}

/** An agent run exceeded its declared timeout, or was cancelled. */
export class AgentRunError extends Error {
  constructor(
    public readonly agentId: string,
    public readonly code: "TIMEOUT" | "CANCELLED" | "FAILED",
    detail: string,
  ) {
    super(`Agent "${agentId}" run ${code}: ${detail}`);
    this.name = "AgentRunError";
  }
}
