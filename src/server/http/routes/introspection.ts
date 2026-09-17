/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Introspection routes: registered agents, run history, the event buffer and
 * the audit log. Everything here reports process state as it is — nothing is
 * rendered from a menu of claims.
 */

import type { Express, Response } from "express";
import { agentManager } from "../../agents/index";
import { listEvents, auditLogsStore } from "../../core/index";

export function registerIntrospectionRoutes(app: Express) {
  /** Registered, executable agents. Zod schemas are omitted (not serializable). */
  app.get("/api/agents", (_req, res: Response) => {
    res.json({
      agents: agentManager.list().map(({ inputSchema: _i, outputSchema: _o, ...rest }) => rest),
    });
  });

  /** Agent run history for this process. */
  app.get("/api/runs", (_req, res: Response) => {
    res.json({ runs: agentManager.listRuns() });
  });

  /** Event stream buffer, newest first. Filter one mission with ?traceId=. */
  app.get("/api/events", (req, res: Response) => {
    const traceId = typeof req.query.traceId === "string" ? req.query.traceId : undefined;
    const limit = Number(req.query.limit) || 100;
    res.json({ events: listEvents({ traceId, limit }) });
  });

  // Audit Logs API
  app.get("/api/logs", (_req, res: Response) => {
    res.json(auditLogsStore);
  });
}