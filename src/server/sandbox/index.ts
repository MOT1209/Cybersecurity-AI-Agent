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
  constructor(public readonly decision: GatewayDecision) {
    super(`Human approval required before executing this high-risk tool: ${decision.reason}`);
    this.name = "ApprovalRequiredError";
  }
}

/**
 * Resolve which executor to use.
 *   SANDBOX_MODE=local  → always simulate
 *   SANDBOX_MODE=docker → Docker, or simulate if the daemon is unreachable
 *   (unset / "auto")    → Docker when available, else simulate
 */
export async function getActiveExecutor(): Promise<ToolExecutor> {
  const mode = (process.env.SANDBOX_MODE || "auto").trim().toLowerCase();
  if (mode === "local") return localSim;
  if (mode === "docker" || mode === "auto") {
    if (await docker.isAvailable()) return docker;
  }
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
  /** Recorded human approval, required for high-risk tools. */
  approved?: boolean;
}

/**
 * Gateway-guarded tool execution. Throws {@link GatewayDeniedError} when the
 * target is out of scope (map to HTTP 403), or {@link ApprovalRequiredError}
 * when a high-risk tool is run without `approved: true` (map to HTTP 428).
 * Never throws for a mere tool failure — that is reported via status/exitCode.
 */
export async function executeTool(p: ExecuteToolParams): Promise<ToolRunResult> {
  const decision = validateSecurityGateway(p.target, p.toolId, p.projectId);
  if (!decision.isAllowed) {
    throw new GatewayDeniedError(decision);
  }
  // Enforce human-in-the-loop for high-risk tools instead of only flagging it.
  if (decision.humanApprovalRequired && p.approved !== true) {
    addAuditLog(
      p.actor || "ToolManager",
      `BLOCKED_${p.toolId.toUpperCase()}`,
      p.target,
      "APPROVAL_REQUIRED",
      `High-risk tool "${p.toolId}" blocked pending explicit human approval.`,
    );
    throw new ApprovalRequiredError(decision);
  }

  let executor = await getActiveExecutor();
  // Docker needs an image; tools without an adapter image run in simulation.
  if (executor.id === "docker" && !p.image) {
    executor = localSim;
  }
  const req: ToolRunRequest = {
    toolId: p.toolId,
    target: p.target,
    args: p.args ?? [],
    image: p.image,
    timeoutMs: p.timeoutMs,
    params: p.params,
  };
  const result = await executor.run(req);

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
