/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * sqlmap adapter — ACTIVE SQL-injection testing against an authorized target.
 * Sends real injection probes, so it is classified HIGH risk (the same tier as
 * zap): the risk policy engine requires explicit human approval for every run
 * regardless of these parameter caps.
 *
 * level/risk are capped below sqlmap's own maximums (5 and 3) so a default run
 * stays low-noise and never selects sqlmap's potentially destructive risk-3
 * payload classes.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";

export const SQLMAP_TOOL_ID = "sqlmap";
export const sqlmapImage = () => process.env.SQLMAP_IMAGE || "sqlmapproject/sqlmap:latest";

export const SqlmapParamsSchema = z.object({
  level: z.number().int().min(1).max(3).optional().default(1),
  risk: z.number().int().min(1).max(2).optional().default(1),
  data: z.string().max(2000).optional(),
});

export type SqlmapParams = z.infer<typeof SqlmapParamsSchema>;

export function buildSqlmapRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = SqlmapParamsSchema.parse(rawParams ?? {});
  const args = ["-u", target, "--batch", "--level", String(params.level), "--risk", String(params.risk)];
  if (params.data) args.push("--data", params.data);
  return {
    toolId: SQLMAP_TOOL_ID,
    target,
    args,
    image: sqlmapImage(),
    params: { ...params },
  };
}

export interface SqlmapFinding {
  parameter: string;
  type: string;
  title: string;
}

/** Best-effort parse of sqlmap's "Parameter: X (Type)" injection banners. */
export function parseSqlmapOutput(raw: string): SqlmapFinding[] {
  const findings: SqlmapFinding[] = [];
  const re = /Parameter:\s+(\S+)\s+\(([^)]+)\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    findings.push({ parameter: m[1], type: m[2], title: `Injectable parameter: ${m[1]}` });
  }
  return findings;
}

export function summarizeSqlmapResult(result: ToolRunResult): ToolRunResult {
  const findings = parseSqlmapOutput(result.rawOutput);
  return {
    ...result,
    structuredData: { ...result.structuredData, findings, vulnerable: findings.length > 0 },
  };
}

export const sqlmapDescriptor: ToolDescriptor = {
  id: SQLMAP_TOOL_ID,
  name: "sqlmap SQL Injection Tester",
  version: "1.0.0",
  description:
    "Active SQL-injection detection and exploitation against an authorized " +
    "target. HIGH risk — every run requires human approval; level/risk are " +
    "capped below sqlmap's own maximums.",
  capabilities: ["web-scan", "sql-injection"],
  inputSchema: SqlmapParamsSchema,
  outputSchemaHint: '{ findings: [{ parameter, type, title }], vulnerable: boolean }',
  permissions: ["network:scan", "web:test"],
  riskLevel: "HIGH",
  timeoutMs: 600_000,
  resourceLimits: { cpus: 1, memoryMb: 1024, pids: 256 },
  sandboxRequired: true,
  needsNetwork: true,
  targetKind: "network",
  filesystemAccess: "none",
  get image() {
    return sqlmapImage();
  },
};

export const sqlmapAdapter: ToolAdapter = {
  descriptor: sqlmapDescriptor,
  build: buildSqlmapRequest,
  parse: summarizeSqlmapResult,
};
