/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Deterministic simulation executor. Requires no Docker daemon and is the
 * default fallback. Reproduces the structured shape the frontend already
 * consumed from the old inline /api/tools/execute simulation, so the UI keeps
 * working unchanged when Docker is unavailable.
 */

import type { ToolExecutor, ToolRunRequest, ToolRunResult } from "./types";
import { DEFAULT_TIMEOUT_MS } from "./types";

export class LocalSimExecutor implements ToolExecutor {
  readonly id = "local-sim" as const;

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(req: ToolRunRequest): Promise<ToolRunResult> {
    const timestamp = new Date().toISOString();
    const containerId = `sbx_${Math.random().toString(36).substring(2, 8)}`;
    const argLine = req.args.length ? ` ${req.args.join(" ")}` : "";
    const rawOutput =
      `!! SIMULATED — NOT A REAL RESULT. No ${req.toolId} process was executed and
` +
      `!! no packet reached ${req.target}. This output exists only because
` +
      `!! SANDBOX_MODE=simulate was set explicitly. Do not treat it as evidence.
` +
      `[sim] would run: ${req.toolId}${argLine} ${req.target}
` +
      `[sim] pseudo-container ${containerId} (no container was created).`;

    return {
      toolId: req.toolId,
      target: req.target,
      timestamp,
      status: "SUCCESS",
      exitCode: 0,
      sandbox: {
        containerId,
        isolated: true,
        cpuLimit: "1.0",
        memoryLimit: "512MB",
        network: "isolated_bridge",
        mode: "local-sim",
      },
      rawOutput,
      structuredData: {
        simulated: true,
        targetHost: req.target,
        scannedAt: timestamp,
        tool: req.toolId,
        args: req.args,
        params: req.params ?? {},
        timeoutMs: req.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      },
    };
  }
}
