/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Security routes: the pre-execution Security Gateway check and the human
 * approval system (list requests, record a decision).
 */

import type { Express, Response } from "express";
import {
  validateStringField,
  validateSecurityGateway,
} from "../../core/index";
import { callerHasRole, principalOf } from "../middleware";
import {
  decideApproval,
  listApprovals,
} from "../../security/approvals";

export function registerSecurityRoutes(app: Express) {
  // Security Gateway Pre-Execution Check API
  app.post("/api/gateway/check", (req, res: Response) => {
    const targetCheck = validateStringField(req.body?.target, "target", 500, false);
    if (!targetCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: targetCheck.error });
    }
    const toolNameCheck = validateStringField(req.body?.toolName, "toolName", 100, false);
    if (!toolNameCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: toolNameCheck.error });
    }
    const projectCheck = validateStringField(req.body?.projectId, "projectId", 100, false);
    if (!projectCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: projectCheck.error });
    }

    const { target = "192.168.1.50", toolName = "nmap", projectId = "proj_alpha_lab" } = req.body;
    const result = validateSecurityGateway(target, toolName, projectId);
    res.json(result);
  });

  // --- Human approval system (§15) ---

  /** Pending and decided approval requests. Tokens are never exposed here. */
  app.get("/api/approvals", (_req, res: Response) => {
    res.json({ approvals: listApprovals() });
  });

  /**
   * Record a human decision. `decidedBy` must differ from the requester, so an
   * automated caller cannot approve its own request. On approval the response
   * carries a single-use token bound to that exact tool+target.
   */
  app.post("/api/approvals/:id/decision", (req, res: Response) => {
    const idCheck = validateStringField(req.params.id, "id", 100, true);
    if (!idCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: idCheck.error });
    }
    const decision = req.body?.decision;
    if (decision !== "APPROVED" && decision !== "REJECTED") {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: "Field 'decision' must be APPROVED or REJECTED." });
    }

    // Authorization, not just authentication: approving is a privileged act.
    if (!callerHasRole(req, "approver")) {
      const principal = principalOf(req);
      return res.status(403).json({
        error: "FORBIDDEN",
        message:
          `Principal "${principal.id}" does not hold the "approver" role. ` +
          "Configure per-key identities via API_PRINCIPALS; the shared APP_ACCESS_KEY " +
          "deliberately cannot approve, because a shared key is not a person.",
      });
    }

    // The decider is the authenticated identity. Accepting it from the body
    // would let a caller name someone else and defeat the self-approval rule.
    const result = decideApproval(req.params.id, decision, principalOf(req).id);
    if (!result.ok) {
      return res.status(409).json({ error: "APPROVAL_CONFLICT", message: result.error });
    }
    return res.json({
      approval: { ...result.approval, token: undefined },
      // Present exactly once. Redeeming it burns it.
      approvalToken: result.approval!.token,
    });
  });
}