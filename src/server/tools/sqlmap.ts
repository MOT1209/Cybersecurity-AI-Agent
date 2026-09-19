/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * sqlmap tool adapter. ACTIVE exploitation tool — sends real injection
 * payloads at the target. The security gateway classifies "sqlmap" as
 * high-risk (see core/gateway.ts highRiskTools) and requires explicit human
 * approval before executeTool() will run it, regardless of these caps.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";

export const SqlmapParamsSchema = z.object({
  // Capped well below sqlmap's max (5): keeps default runs low-noise.
  level: z.number().int().min(1).max(3).optional().default(1),
  // Capped below sqlmap's max (3): risk 3 includes potentially destructive payloads.
  risk: z.number().int().min(1).max(2).optional().default(1),
  data: z.string().max(2000).optional(),
});

export type SqlmapParams = z.infer<typeof SqlmapParamsSchema>;

export const SQLMAP_TOOL_ID = "sqlmap";
export const sqlmapImage = () => process.env.SQLMAP_IMAGE || "sqlmapproject/sqlmap:latest";

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
