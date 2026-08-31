/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sandbox facade. Resolves the active executor (real Docker when available,
 * otherwise the deterministic simulation) and exposes `executeTool`, the single
 * entry point that enforces the security gateway, runs the tool, and records an
 * audit entry with a sha256 of the raw output for report traceability.
 */

import { validateSecurityGateway, addAuditLog } from "../core/index";
import { emitEvent } from "../core/events";
import { consumeApproval } from "../security/approvals";
import type { ApprovalOutcome } from "../security/approvals";
import { ToolNotAvailableError, ToolNotRegisteredError } from "../core/errors";
import { isToolRegistered, hasAdapter } from "../tools/registry";
import type { GatewayDecision } from "../core/gateway";
import { LocalSimExecutor } from "./localSim";
import { DockerExecutor } from "./docker";
import type { ToolExecutor, ToolRunRequest, ToolRunResult } from "./types";

export * from "./types";

const localSim = new LocalSimExecutor();
const docker = new DockerExecutor();

/** Thrown when the security gateway denies a target/tool combination. */
export class GatewayDeniedError extends Error {
  constructor(public readonly decision: GatewayDecision) {
    super(decision.reason);
    this.name = "GatewayDeniedError";
  }
}

/**
 * Thrown when a high-risk tool needs explicit human approval that was not
 * granted. The caller must pass `approved: true` (a recorded human decision)
 * to proceed. Map to HTTP 428 (Precondition Required) at the route.
 */
export class ApprovalRequiredError extends Error {
  constructor(
    public readonly decision: GatewayDecision,
    public readonly detail?: string,
  ) {
    super(
      `Human approval required before executing this ${decision.riskLevel}-risk tool` +
        (detail ? `: ${detail}` : "."),
    );
    this.name = "ApprovalRequiredError";
  }
}

/**
 * Sandbox mode, normalized. "local" is retained as an alias of "simulate" for
 * backwards compatibility with existing configuration.
 */
export type SandboxMode = "auto" | "docker" | "simulate";

export function resolveSandboxMode(): SandboxMode {
  const raw = (process.env.SANDBOX_MODE || "auto").trim().toLowerCase();
  if (raw === "local" || raw === "simulate") return "simulate";
  if (raw === "docker") return "docker";
  return "auto";
}

/**
 * Resolve the executor for a tool run, or throw {@link ToolNotAvailableError}.
 *
 * This is the honest-failure contract (§40): simulation is only ever used when
 * an operator explicitly opted into it via SANDBOX_MODE. In "auto"/"docker",
 * an unreachable Docker daemon is a hard failure, not a silent downgrade into
 * fabricated output.
 */
export async function resolveExecutor(toolId: string): Promise<ToolExecutor> {
  const mode = resolveSandboxMode();
  if (mode === "simulate") return localSim;

  if (await docker.isAvailable()) return docker;

  throw new ToolNotAvailableError(
    toolId,
    "the Docker sandbox is unreachable and SANDBOX_MODE is not \"simulate\", " +
      "so no real isolated executor is available. Start Docker, or set " +
      "SANDBOX_MODE=simulate to explicitly accept clearly-labelled simulated output.",
  );
}

/**
 * Backwards-compatible accessor used by diagnostics. Returns the simulation
 * executor when Docker is unreachable rather than throwing.
 */
export async function getActiveExecutor(): Promise<ToolExecutor> {
  if (resolveSandboxMode() !== "simulate" && (await docker.isAvailable())) return docker;
  return localSim;
}

export interface ExecuteToolParams {
  toolId: string;
  target: string;
  args?: string[];
  image?: string;
  timeoutMs?: number;
  params?: Record<string, unknown>;
  projectId?: string;
  actor?: string;
  /**
   * Single-use approval token minted by the approval system after a human
   * decision. Required for any tool the risk policy gates on approval.
   * A boolean flag is deliberately NOT accepted — a caller must not be able to
   * authorize its own request.
   */
  approvalToken?: string;
  /** Correlates this run with the mission/agent that requested it. */
  traceId?: string;
}

/**
 * Gateway-guarded tool execution. Throws {@link GatewayDeniedError} when the
 * target is out of scope (map to HTTP 403), or {@link ApprovalRequiredError}
 * when a high-risk tool is run without `approved: true` (map to HTTP 428).
 * Never throws for a mere tool failure — that is reported via status/exitCode.
 */
export async function executeTool(p: ExecuteToolParams): Promise<ToolRunResult> {
  const traceId = p.traceId;
  emitEvent("TOOL_REQUESTED", { traceId, toolId: p.toolId, target: p.target, projectId: p.projectId });

  // 0. Registry: unknown tools are denied outright (fail closed).
  if (!isToolRegistered(p.toolId)) {
    emitEvent("TOOL_DENIED", { traceId, toolId: p.toolId, target: p.target, detail: "not registered" });
    addAuditLog(
      p.actor || "ToolManager",
      `BLOCKED_${p.toolId.toUpperCase()}`,
      p.target,
      "DENIED",
      `Unregistered tool "${p.toolId}" rejected by the tool registry.`,
    );
    throw new ToolNotRegisteredError(p.toolId);
  }

  const decision = validateSecurityGateway(p.target, p.toolId, p.projectId);
  if (!decision.isAllowed) {
    emitEvent("TOOL_DENIED", { traceId, toolId: p.toolId, target: p.target, detail: decision.reason });
    throw new GatewayDeniedError(decision);
  }
  // Enforce human-in-the-loop for high-risk tools instead of only flagging it.
  if (decision.humanApprovalRequired) {
    const redeemed: ApprovalOutcome = p.approvalToken
      ? consumeApproval(p.approvalToken, p.toolId, p.target)
      : { ok: false, error: "No approval token supplied." };
    if (!redeemed.ok) {
      addAuditLog(
        p.actor || "ToolManager",
        `BLOCKED_${p.toolId.toUpperCase()}`,
        p.target,
        "APPROVAL_REQUIRED",
        `${decision.riskLevel}-risk tool "${p.toolId}" blocked: ${redeemed.error}`,
      );
      emitEvent("TOOL_DENIED", { traceId, toolId: p.toolId, target: p.target, detail: redeemed.error });
      throw new ApprovalRequiredError(decision, redeemed.error);
    }
  }

  // A registered tool with no adapter cannot produce a real result. Saying so
  // is the whole point — never emit a fabricated SUCCESS for it.
  if (!hasAdapter(p.toolId) && resolveSandboxMode() !== "simulate") {
    addAuditLog(
      p.actor || "ToolManager",
      `BLOCKED_${p.toolId.toUpperCase()}`,
      p.target,
      "NOT_AVAILABLE",
      `Tool "${p.toolId}" is declared in the registry but has no implemented adapter.`,
    );
    emitEvent("TOOL_NOT_AVAILABLE", { traceId, toolId: p.toolId, target: p.target, detail: "no adapter implemented" });
    throw new ToolNotAvailableError(
      p.toolId,
      "it is declared in the registry but has no implemented adapter yet",
    );
  }

  emitEvent("TOOL_APPROVED", { traceId, toolId: p.toolId, target: p.target, detail: `risk=${decision.riskLevel}` });

  let executor: ToolExecutor;
  try {
    executor = await resolveExecutor(p.toolId);
  } catch (err) {
    emitEvent("TOOL_NOT_AVAILABLE", { traceId, toolId: p.toolId, target: p.target, detail: (err as Error).message });
    throw err;
  }
  const req: ToolRunRequest = {
    toolId: p.toolId,
    target: p.target,
    args: p.args ?? [],
    image: p.image,
    timeoutMs: p.timeoutMs,
    params: p.params,
  };
  if (executor.id === "docker" && !req.image) {
    throw new ToolNotAvailableError(
      p.toolId,
      "no container image is configured for this tool, so it cannot run in the Docker sandbox",
    );
  }
  emitEvent("TOOL_STARTED", { traceId, toolId: p.toolId, target: p.target, detail: `sandbox=${executor.id}` });
  const result = await executor.run(req);
  emitEvent("TOOL_COMPLETED", {
    traceId,
    toolId: p.toolId,
    target: p.target,
    detail: `status=${result.status} exit=${result.exitCode} sandbox=${result.sandbox.mode}`,
  });

  addAuditLog(
    p.actor || "ToolManager",
    `RUN_${p.toolId.toUpperCase()}`,
    p.target,
    result.status === "SUCCESS" ? "COMPLETED" : result.status,
    `Tool executed in ${result.sandbox.mode} sandbox (container ${result.sandbox.containerId}, exit ${result.exitCode})`,
    result.rawOutput,
  );

  return result;
}

export { ToolNotAvailableError, ToolNotRegisteredError };
