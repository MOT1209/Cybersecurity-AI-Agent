/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Labs routes (§17). Container state is read from Docker — a lab whose
 * container is gone reports STOPPED, never RUNNING by assumption, and an
 * unreachable daemon reports UNKNOWN, because "not observed" is not "off".
 */

import type { Express, Response } from "express";
import { validateStringField } from "../../core/index";
import { ToolNotAvailableError } from "../../core/errors";
import { listLabStates, getLabState, startLab, stopLab } from "../../labs/manager";
import { principalOf } from "../middleware";

export function registerLabsRoutes(app: Express) {
  app.get("/api/labs", async (_req, res: Response) => {
    res.json({ labs: await listLabStates() });
  });

  app.get("/api/labs/:id", async (req, res: Response) => {
    try {
      res.json(await getLabState(req.params.id));
    } catch (err) {
      res.status(404).json({ error: "UNKNOWN_LAB", message: (err as Error).message });
    }
  });

  /**
   * Start a lab. The id must come from the fixed catalog: accepting an image
   * reference here would be remote code execution by API.
   */
  app.post("/api/labs/:id/start", async (req, res: Response) => {
    const idCheck = validateStringField(req.params.id, "id", 100, true);
    if (!idCheck.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: idCheck.error });
    }
    try {
      res.json(await startLab(req.params.id, principalOf(req).id));
    } catch (err) {
      if (err instanceof ToolNotAvailableError) {
        return res.status(503).json({ error: err.code, message: err.message, reason: err.detail });
      }
      return res.status(400).json({ error: "LAB_START_FAILED", message: (err as Error).message });
    }
  });

  app.post("/api/labs/:id/stop", async (req, res: Response) => {
    try {
      res.json(await stopLab(req.params.id, principalOf(req).id));
    } catch (err) {
      if (err instanceof ToolNotAvailableError) {
        return res.status(503).json({ error: err.code, message: err.message, reason: err.detail });
      }
      return res.status(400).json({ error: "LAB_STOP_FAILED", message: (err as Error).message });
    }
  });
}