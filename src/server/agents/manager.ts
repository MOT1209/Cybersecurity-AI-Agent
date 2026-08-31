/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Agent Manager (§6). Owns agent registration, discovery, permissions and the
 * run lifecycle (timeout, cancellation, error capture, run records).
 *
 * The orchestrator dispatches through this manager and never imports a concrete
 * agent, so adding an agent is a registration, not an edit to the workflow.
 */

import crypto from "crypto";
import { AgentNotRegisteredError, AgentRunError } from "../core/errors";
import { addAuditLog } from "../core/store";
import { emitEvent } from "../core/events";
import { isToolRegistered } from "../tools/registry";
import type { AgentResult } from "./base";
import type {
  AgentDescriptor,
  AgentRunContext,
  AgentRunRecord,
  RunnableAgent,
} from "./types";

export interface DispatchOptions {
  projectId?: string;
  traceId?: string;
  /** Overrides the agent's declared timeout. */
  timeoutMs?: number;
  /** Caller-owned cancellation. */
  signal?: AbortSignal;
}

export class AgentManager {
  private readonly agents = new Map<string, RunnableAgent>();
  private readonly runs: AgentRunRecord[] = [];
  private readonly inFlight = new Map<string, AbortController>();

  /**
   * Register an agent. Rejects a descriptor whose `allowedTools` reference a
   * tool that does not exist — a broken allowlist must fail at startup, not
   * silently widen at execution time.
   */
  register(agent: RunnableAgent): void {
    const d = agent.describe();
    const unknown = d.allowedTools.filter((t) => !isToolRegistered(t));
    if (unknown.length) {
      throw new Error(
        `Agent "${d.id}" declares unregistered tools: ${unknown.join(", ")}`,
      );
    }
    this.agents.set(d.id, agent);
  }

  has(agentId: string): boolean {
    return this.agents.has(agentId);
  }

  get(agentId: string): RunnableAgent {
    const a = this.agents.get(agentId);
    if (!a) throw new AgentNotRegisteredError(agentId);
    return a;
  }

  /** Discovery: all registered agent descriptors. */
  list(): AgentDescriptor[] {
    return [...this.agents.values()]
      .map((a) => a.describe())
      .sort((x, y) => x.id.localeCompare(y.id));
  }

  /** Agents whose capabilities include every requested capability. */
  findByCapability(...capabilities: string[]): AgentDescriptor[] {
    return this.list().filter((d) =>
      capabilities.every((c) => d.capabilities.includes(c)),
    );
  }

  /** Run history, newest first (capped in memory until persistence lands). */
  listRuns(): AgentRunRecord[] {
    return [...this.runs];
  }

  /** Cancel an in-flight run. Returns false when the run is already finished. */
  cancel(runId: string): boolean {
    const ctrl = this.inFlight.get(runId);
    if (!ctrl) return false;
    ctrl.abort();
    return true;
  }

  /**
   * Dispatch a task to an agent under its declared timeout, recording the run.
   * Errors the agent raises (including a gateway denial) propagate unchanged so
   * the caller can map them to the right HTTP status.
   */
  async dispatch<T = unknown>(
    agentId: string,
    input: unknown,
    opts: DispatchOptions = {},
  ): Promise<AgentResult<T>> {
    const agent = this.get(agentId);
    const d = agent.describe();

    const runId = `run_${crypto.randomUUID()}`;
    const traceId = opts.traceId ?? `trc_${crypto.randomUUID()}`;
    const projectId = opts.projectId ?? "proj_alpha_lab";
    const timeoutMs = opts.timeoutMs ?? d.timeoutMs;

    const record: AgentRunRecord = {
      runId,
      agentId,
      traceId,
      projectId,
      state: "RUNNING",
      startedAt: new Date().toISOString(),
    };
    this.runs.unshift(record);
    if (this.runs.length > 200) this.runs.pop();

    const ctrl = new AbortController();
    this.inFlight.set(runId, ctrl);
    const onExternalAbort = () => ctrl.abort();
    opts.signal?.addEventListener("abort", onExternalAbort);

    emitEvent("AGENT_STARTED", { traceId, runId, agentId, projectId });

    const started = Date.now();
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        ctrl.abort();
        reject(new AgentRunError(agentId, "TIMEOUT", `exceeded ${timeoutMs}ms`));
      }, timeoutMs);
    });

    const ctx: AgentRunContext = { traceId, projectId, signal: ctrl.signal };

    try {
      const result = (await Promise.race([
        agent.run(input, ctx),
        timeout,
      ])) as AgentResult<T>;
      record.state = "COMPLETED";
      emitEvent("AGENT_COMPLETED", { traceId, runId, agentId, projectId });
      return result;
    } catch (err) {
      const e = err as Error;
      record.state =
        e instanceof AgentRunError && e.code === "TIMEOUT" ? "TIMEOUT" : "FAILED";
      record.error = e.message;
      emitEvent("TASK_FAILED", { traceId, runId, agentId, projectId, detail: e.message });
      addAuditLog(
        "AgentManager",
        `AGENT_${agentId.toUpperCase()}`,
        String((input as { target?: string })?.target ?? "-"),
        record.state,
        `Agent run ${runId} ${record.state}: ${e.message}`,
      );
      throw err;
    } finally {
      if (timer) clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onExternalAbort);
      this.inFlight.delete(runId);
      record.finishedAt = new Date().toISOString();
      record.durationMs = Date.now() - started;
    }
  }
}

export const agentManager = new AgentManager();
