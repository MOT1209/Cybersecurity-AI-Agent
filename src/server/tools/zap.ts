/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * OWASP ZAP baseline-scan adapter. Runs the official ZAP baseline script in a
 * container against an in-scope target and parses the WARN-NEW / FAIL-NEW
 * summary lines into structured alert findings.
 *
 * Deliberately the *baseline* script, not the full scan: it spiders briefly
 * and runs passive rules, so a run finishes inside the declared timeout
 * instead of crawling the target for hours. Depth is a caller-visible param
 * (`spiderMinutes`, capped), never an open-ended default.
 *
 * HIGH risk: DAST sends attack payloads at a live target, so every run passes
 * through the approval gate like any other high-risk tool.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";

export const ZAP_TOOL_ID = "zap";
export const zapImage = () => process.env.ZAP_IMAGE || "ghcr.io/zaproxy/zaproxy:stable";

export const ZapParamsSchema = z.object({
  /** Spider duration in minutes. Capped: depth must stay a caller decision. */
  spiderMinutes: z.number().int().min(1).max(30).optional().default(2),
});

export type ZapParams = z.infer<typeof ZapParamsSchema>;

/** Build a sandbox run request for `zap-baseline.py -t <target>`. */
export function buildZapRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = ZapParamsSchema.parse(rawParams ?? {});
  const args = ["zap-baseline.py", "-t", target, "-m", String(params.spiderMinutes)];
  return {
    toolId: ZAP_TOOL_ID,
    target,
    args,
    image: zapImage(),
    params: { ...params },
  };
}

export interface ZapAlert {
  /** NEW (first seen) vs INPROG (carried over): only NEW counts as a finding. */
  state: "NEW" | "INPROG";
  severity: "FAIL" | "WARN";
  name: string;
  /** ZAP plugin id in brackets, e.g. "10049". Absent when the line has none. */
  pluginId: string | null;
  occurrences: number;
}

/**
 * Parse zap-baseline.py summary lines, e.g.
 *   "WARN-NEW: Storable and Cacheable Content [10049] x 32"
 *   "FAIL-NEW: SQL Injection [40018] x 2"
 * Returns [] for output without summary lines — including empty output, which
 * means "no scan summary", never "no vulnerabilities".
 */
export function parseZapOutput(raw: string): ZapAlert[] {
  const alerts: ZapAlert[] = [];
  const re = /^(FAIL|WARN)-(NEW|INPROG):\s*(.+?)(?:\s*\[(\d+)\])?\s*x\s*(\d+)\s*$/;
  for (const line of raw.split(/\r?\n/)) {
    const m = re.exec(line.trim());
    if (!m) continue;
    // A bare "FAIL-NEW: 0  WARN-NEW: 19 ..." totals line has no "x N" tail
    // per alert and carries no usable finding; the regex above skips it.
    alerts.push({
      severity: m[1] as "FAIL" | "WARN",
      state: m[2] as "NEW" | "INPROG",
      name: m[3].trim(),
      pluginId: m[4] ?? null,
      occurrences: Number(m[5]),
    });
  }
  return alerts;
}

/** Enrich a raw ZAP ToolRunResult with parsed alert findings. */
export function summarizeZapResult(result: ToolRunResult): ToolRunResult {
  const alerts = parseZapOutput(result.rawOutput);
  const fresh = alerts.filter((a) => a.state === "NEW");
  return {
    ...result,
    structuredData: {
      ...result.structuredData,
      alerts,
      newAlertCount: fresh.length,
      failCount: fresh.filter((a) => a.severity === "FAIL").length,
      warnCount: fresh.filter((a) => a.severity === "WARN").length,
    },
  };
}

/** Registry descriptor for the ZAP adapter. */
export const zapDescriptor: ToolDescriptor = {
  id: ZAP_TOOL_ID,
  name: "OWASP ZAP Baseline DAST Scanner",
  version: "1.0.0",
  description:
    "Dynamic application testing via the official ZAP baseline script: brief " +
    "spider plus passive rules against an in-scope target. HIGH risk — every " +
    "run requires human approval.",
  capabilities: ["web-scan", "dast"],
  inputSchema: ZapParamsSchema,
  outputSchemaHint:
    '{ alerts: [{ severity: FAIL|WARN, state: NEW|INPROG, name, pluginId, occurrences }], newAlertCount, failCount, warnCount }',
  permissions: ["network:scan", "web:test"],
  riskLevel: "HIGH",
  timeoutMs: 900_000,
  resourceLimits: { cpus: 2, memoryMb: 2048, pids: 512 },
  sandboxRequired: true,
  needsNetwork: true,
  targetKind: "network",
  filesystemAccess: "none",
  get image() {
    return zapImage();
  },
};

/** The executable ZAP adapter registered in the tool registry. */
export const zapAdapter: ToolAdapter = {
  descriptor: zapDescriptor,
  build: buildZapRequest,
  parse: summarizeZapResult,
};
