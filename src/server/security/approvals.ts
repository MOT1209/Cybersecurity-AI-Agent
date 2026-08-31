/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Human approval system (§15).
 *
 * The security property this module exists to provide: a caller cannot approve
 * its own request. Previously `approved: true` was read straight off the
 * request body, so anyone who could invoke a tool could authorize it. Now the
 * server mints an approval request, a human must act on it through a separate
 * endpoint, and execution consumes a single-use, target/tool-bound token.
 */

import crypto from "crypto";
import { addAuditLog } from "../core/store";
import { emitEvent } from "../core/events";
import type { RiskLevel } from "../tools/types";

export type ApprovalStatus = "PENDING" | "APPROVED" | "REJECTED" | "CONSUMED" | "EXPIRED";

export interface ApprovalRequest {
  id: string;
  /** Single-use secret returned only on approval; presented at execution. */
  token?: string;
  status: ApprovalStatus;
  /** Everything a human needs to make the decision (§15). */
  task: string;
  target: string;
  toolId: string;
  reason: string;
  scope: string;
  riskLevel: RiskLevel;
  expectedImpact: string;
  projectId: string;
  requestedBy: string;
  traceId?: string;
  createdAt: string;
  decidedAt?: string;
  decidedBy?: string;
  expiresAt: string;
}

/** Discriminated outcome for the decision/redemption operations. */
export type ApprovalOutcome =
  | { ok: true; approval: ApprovalRequest; error?: undefined }
  | { ok: false; error: string; approval?: undefined };

const approvals: ApprovalRequest[] = [];

const TTL_MS = Number(process.env.APPROVAL_TTL_MS) || 15 * 60 * 1000;

function expireStale(): void {
  const now = Date.now();
  for (const a of approvals) {
    if ((a.status === "PENDING" || a.status === "APPROVED") && Date.parse(a.expiresAt) < now) {
      a.status = "EXPIRED";
      delete a.token;
    }
  }
}

export interface CreateApprovalInput {
  task: string;
  target: string;
  toolId: string;
  reason: string;
  scope: string;
  riskLevel: RiskLevel;
  expectedImpact: string;
  projectId: string;
  requestedBy: string;
  traceId?: string;
}

/** Open an approval request. Returns the record WITHOUT a token. */
export function createApprovalRequest(input: CreateApprovalInput): ApprovalRequest {
  const now = Date.now();
  const req: ApprovalRequest = {
    id: `apr_${crypto.randomUUID()}`,
    status: "PENDING",
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + TTL_MS).toISOString(),
    ...input,
  };
  approvals.unshift(req);
  if (approvals.length > 200) approvals.pop();

  addAuditLog(
    input.requestedBy,
    `APPROVAL_REQUESTED_${input.toolId.toUpperCase()}`,
    input.target,
    "PENDING",
    `Approval ${req.id} opened for ${input.riskLevel}-risk tool "${input.toolId}": ${input.reason}`,
  );
  return req;
}

/**
 * Record a human decision. `decidedBy` identifies the operator; it must differ
 * from `requestedBy` so an automated caller cannot approve its own request.
 */
export function decideApproval(
  id: string,
  decision: "APPROVED" | "REJECTED",
  decidedBy: string,
): ApprovalOutcome {
  expireStale();
  const a = approvals.find((x) => x.id === id);
  if (!a) return { ok: false, error: `Approval "${id}" not found.` };
  if (a.status !== "PENDING") {
    return { ok: false, error: `Approval "${id}" is ${a.status} and can no longer be decided.` };
  }
  if (decidedBy.trim().toLowerCase() === a.requestedBy.trim().toLowerCase()) {
    return { ok: false, error: "Self-approval is not permitted: the approver must differ from the requester." };
  }

  a.status = decision;
  a.decidedAt = new Date().toISOString();
  a.decidedBy = decidedBy;
  if (decision === "APPROVED") {
    a.token = crypto.randomBytes(32).toString("hex");
  }

  addAuditLog(
    decidedBy,
    `APPROVAL_${decision}_${a.toolId.toUpperCase()}`,
    a.target,
    decision,
    `Approval ${a.id} ${decision.toLowerCase()} by ${decidedBy} for tool "${a.toolId}".`,
  );
  emitEvent(decision === "APPROVED" ? "TOOL_APPROVED" : "TOOL_DENIED", {
    traceId: a.traceId,
    toolId: a.toolId,
    target: a.target,
    projectId: a.projectId,
    detail: `approval ${a.id} ${decision.toLowerCase()} by ${decidedBy}`,
  });
  return { ok: true, approval: a };
}

/**
 * Redeem an approval token for one execution. The token is bound to the exact
 * tool and target it was granted for, and is burned on use.
 */
export function consumeApproval(
  token: string,
  toolId: string,
  target: string,
): ApprovalOutcome {
  expireStale();
  if (!token) return { ok: false, error: "No approval token supplied." };
  const a = approvals.find((x) => x.token && x.token === token);
  if (!a) return { ok: false, error: "Approval token is unknown, already used, or expired." };
  if (a.status !== "APPROVED") return { ok: false, error: `Approval ${a.id} is ${a.status}.` };
  if (a.toolId !== toolId || a.target !== target) {
    return {
      ok: false,
      error: `Approval ${a.id} was granted for ${a.toolId}@${a.target} and cannot be reused for ${toolId}@${target}.`,
    };
  }
  a.status = "CONSUMED";
  delete a.token;
  addAuditLog(
    "SecurityGateway",
    `APPROVAL_CONSUMED_${toolId.toUpperCase()}`,
    target,
    "CONSUMED",
    `Approval ${a.id} redeemed for a single execution of "${toolId}".`,
  );
  return { ok: true, approval: a };
}

/** Listing for the API/UI. Tokens are never exposed. */
export function listApprovals(): Omit<ApprovalRequest, "token">[] {
  expireStale();
  return approvals.map(({ token: _token, ...rest }) => rest);
}

/** Test helper. */
export function resetApprovals(): void {
  approvals.length = 0;
}
