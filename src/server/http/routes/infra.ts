/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Infrastructure routes: health, persistence posture, project registry, and
 * the run-mode switch (`/api/runtime/mode`).
 */

import type { Express, Response } from "express";
import crypto from "crypto";
import {
  validateStringField,
  projectsStore,
  addAuditLog,
} from "../../core/index";
import { databaseStatus } from "../../database/index";
import { requireRole } from "../middleware";
import {
  RUN_MODES,
  DEFAULT_RUN_MODE,
  isRunMode,
  getRunMode,
  setRunMode,
  gateFor,
  RUN_GATES,
} from "../../runtime/index";

export function registerInfraRoutes(app: Express) {
  // Health Check — public, unauthenticated endpoint: keep it free of internal
  // details (key presence, versions, capacity) that aid reconnaissance.
  app.get("/api/health", (_req, res: Response) => {
    res.json({
      status: "ok",
      platform: "CYBERGUARD AI",
      timestamp: new Date().toISOString(),
    });
  });

  /**
   * Persistence posture. Authenticated, because "we are running in memory and
   * lose everything on restart" is operational detail, not public information.
   * Never includes the connection string.
   */
  app.get("/api/database/status", async (_req, res: Response) => {
    res.json(await databaseStatus());
  });

  // --- Projects API ---
  app.get("/api/projects", (_req, res: Response) => {
    res.json(projectsStore);
  });

  app.post("/api/projects", (req, res: Response) => {
    const nameCheck = validateStringField(req.body?.name, "name", 200, false);
    if (!nameCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: nameCheck.error });
    }
    const targetDomainCheck = validateStringField(req.body?.targetDomain, "targetDomain", 200, false);
    if (!targetDomainCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: targetDomainCheck.error });
    }

    const { name, targetDomain, inScope = [], outOfScope = [] } = req.body;
    // Creating an engagement (new scope!) is an admin act.
    if (!requireRole(req, res, "admin")) return;
    const newProj = {
      id: `proj_${crypto.randomUUID()}`,
      name: name || "New Security Engagement Lab",
      targetDomain: targetDomain || "target.lab",
      targetIps: [targetDomain || "192.168.1.50"],
      inScope,
      outOfScope,
      allowedTools: ["nmap", "nuclei", "semgrep", "trivy", "zap"],
      policy: { strictSandbox: true, requireApprovalForHighRisk: true },
    };
    projectsStore.push(newProj);
    addAuditLog("Admin", "CREATE_PROJECT", newProj.targetDomain, "COMPLETED", `New project engagement created: ${newProj.name}`);
    res.json(newProj);
  });

  // --- Run mode (§ P1) ---

  /**
   * Current run mode plus the immutable gates of every mode, so the caller can
   * read what switching would flip before it flips anything. Lab egress itself
   * stays a separate operator switch (SANDBOX_ALLOW_EGRESS) — the mode selects
   * enforcement layers, not sandbox port-open policy.
   */
  app.get("/api/runtime/mode", (_req, res: Response) => {
    res.json({
      current: getRunMode(),
      default: DEFAULT_RUN_MODE,
      modes: Object.fromEntries(RUN_MODES.map((m) => [m, RUN_GATES[m]])),
      note:
        "Run mode selects the active enforcement layers. Lab network egress is a " +
        "separate operator switch (SANDBOX_ALLOW_EGRESS) layered on top of the mode.",
    });
  });

  app.post("/api/runtime/mode", (req, res: Response) => {
    const check = validateStringField(req.body?.mode, "mode", 50, true);
    if (!check.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: check.error });
    }
    if (!isRunMode(req.body.mode)) {
      return res.status(400).json({
        error: "VALIDATION_ERROR",
        message: `Field 'mode' must be one of: ${RUN_MODES.join(", ")}.`,
      });
    }
    // Switching enforcement layers is an admin act.
    if (!requireRole(req, res, "admin")) return;
    const mode = req.body.mode;
    const previous = getRunMode();
    setRunMode(mode);
    addAuditLog("Admin", "SET_RUN_MODE", "Runtime", "COMPLETED", `Run mode switched from ${previous} to ${mode}.`);
    res.json({ current: mode, previous, gate: gateFor(mode) });
  });
}