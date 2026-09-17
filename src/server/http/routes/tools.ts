/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tool routes: registry listing, real health probes, and the generic sandbox
 * execution endpoint with its honest-failure mapping. The execution handler is
 * the largest route in the platform: gateway, approvals, workspace path
 * resolution and adapter dispatch all meet here.
 */

import type { Express, Response } from "express";
import { ZodError } from "zod";
import { validateStringField } from "../../core/index";
import {
  ToolNotAvailableError,
  ToolNotRegisteredError,
} from "../../core/errors";
import { listTools, getToolAdapter, getToolDescriptor } from "../../tools/registry";
import { checkAllToolHealth, checkToolHealth } from "../../tools/health";
import { resolveWorkspacePath } from "../../security/workspace";
import {
  executeTool,
  GatewayDeniedError,
  ApprovalRequiredError,
} from "../../sandbox/index";
import { createApprovalRequest } from "../../security/approvals";
import { principalOf } from "../middleware";

export function registerToolsRoutes(app: Express) {
  /** Tool registry listing. `implemented` distinguishes a real adapter from a
   *  declared-only catalog entry — the UI must not show the latter as usable. */
  app.get("/api/tools", (_req, res: Response) => {
    res.json({ tools: listTools() });
  });

  /** Real health probes. Never reports a tool as installed without verifying. */
  app.get("/api/tools/health", async (_req, res: Response) => {
    res.json({ tools: await checkAllToolHealth() });
  });

  app.get("/api/tools/:toolId/health", async (req, res: Response) => {
    const check = validateStringField(req.params.toolId, "toolId", 100, true);
    if (!check.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: check.error });
    }
    res.json(await checkToolHealth(req.params.toolId));
  });

  // Individual Tool Sandbox Execution API
  app.post("/api/tools/execute", async (req, res: Response) => {
    const toolIdCheck = validateStringField(req.body?.toolId, "toolId", 100, true);
    if (!toolIdCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: toolIdCheck.error });
    }
    const targetCheck = validateStringField(req.body?.target, "target", 500, false);
    if (!targetCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: targetCheck.error });
    }
    const projectCheck = validateStringField(req.body?.projectId, "projectId", 100, false);
    if (!projectCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: projectCheck.error });
    }

    const { toolId, target = "192.168.1.50", params = {}, projectId = "proj_alpha_lab", approvalToken } = req.body;

    try {
      // Generic adapter dispatch: whichever adapter the registry holds for this
      // tool validates the params, builds the argv and parses the output. There
      // is no per-tool branching and no silent path for an unknown tool.
      const adapter = getToolAdapter(toolId);
      const descriptor = getToolDescriptor(toolId);
      let executionResult;
      if (adapter) {
        // Filesystem-scoped tools take a path, not a host. Resolve it against
        // the workspace root FIRST — the tool only ever sees the contained
        // container-side path, and the mount is read-only.
        let scanTarget = target;
        let workspaceHostPath: string | undefined;
        if (descriptor?.targetKind === "filesystem") {
          const resolved = await resolveWorkspacePath(target);
          if (!resolved.ok) {
            return res.status(400).json({ error: "WORKSPACE_PATH_REJECTED", message: resolved.error });
          }
          scanTarget = resolved.containerPath!;
          workspaceHostPath = resolved.hostPath!;
        }
        const built = adapter.build(scanTarget, params);
        const raw = await executeTool({
          toolId,
          target: built.target,
          args: built.args,
          image: built.image,
          params: built.params,
          projectId,
          approvalToken,
          workspaceHostPath,
        });
        executionResult = adapter.parse(raw);
      } else {
        // Registered but unimplemented: executeTool raises NOT_AVAILABLE unless
        // simulation was explicitly opted into.
        executionResult = await executeTool({ toolId, target, params, projectId, approvalToken });
      }
      return res.json(executionResult);
    } catch (err) {
      if (err instanceof GatewayDeniedError) {
        return res.status(403).json({ error: "BLOCKED_BY_GATEWAY", message: err.decision.reason });
      }
      if (err instanceof ApprovalRequiredError) {
        // Open an approval request so a human has something concrete to act on,
        // and hand back its id. The caller cannot approve it itself.
        const approval = createApprovalRequest({
          task: `Execute ${toolId} against ${target}`,
          target,
          toolId,
          reason: err.detail || "Risk policy requires explicit human approval.",
          scope: projectId,
          riskLevel: err.decision.riskLevel,
          expectedImpact: `Runs the "${toolId}" security tool inside the sandbox against ${target}.`,
          projectId,
          requestedBy: principalOf(req).id,
        });
        return res.status(428).json({
          error: "APPROVAL_REQUIRED",
          message: err.message,
          humanApprovalRequired: true,
          approvalId: approval.id,
          approval: { ...approval, token: undefined },
        });
      }
      if (err instanceof ToolNotRegisteredError) {
        return res.status(400).json({ error: err.code, message: err.message });
      }
      if (err instanceof ToolNotAvailableError) {
        // Honest failure (§40): the tool did not run, and we say exactly why.
        return res.status(503).json({ error: err.code, toolId: err.toolId, message: err.message, reason: err.detail });
      }
      if (err instanceof ZodError) {
        return res.status(400).json({ error: "VALIDATION_ERROR", message: err.issues.map((i) => i.message).join("; ") });
      }
      return res.status(500).json({ error: "TOOL_EXECUTION_ERROR", message: (err as Error).message });
    }
  });
}