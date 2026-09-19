/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * XSStrike tool adapter. ACTIVE exploitation tool — injects real XSS payloads
 * against the target. The security gateway classifies "xsstrike" as
 * high-risk (see core/gateway.ts highRiskTools) and requires explicit human
 * approval before executeTool() will run it.
 *
 * NOTE: there is no official Docker Hub image for XSStrike. XSSTRIKE_IMAGE
 * must be pinned to an image you've built/reviewed before production use.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";

export const XsstrikeParamsSchema = z.object({
  crawl: z.boolean().optional().default(false),
});

export type XsstrikeParams = z.infer<typeof XsstrikeParamsSchema>;

export const XSSTRIKE_TOOL_ID = "xsstrike";
export const xsstrikeImage = () => process.env.XSSTRIKE_IMAGE || "ghcr.io/s0md3v/xsstrike:latest";

export function buildXsstrikeRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = XsstrikeParamsSchema.parse(rawParams ?? {});
  // --skip: don't block on XSStrike's interactive confirmation prompts.
  const args = ["-u", target, "--skip"];
  if (params.crawl) args.push("--crawl", "2");
  return {
    toolId: XSSTRIKE_TOOL_ID,
    target,
    args,
    image: xsstrikeImage(),
    params: { ...params },
  };
}

export interface XsstrikeFinding {
  payload: string;
  context: string;
}

export function parseXsstrikeOutput(raw: string): XsstrikeFinding[] {
  const findings: XsstrikeFinding[] = [];
  const re = /Payload:\s*(.+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    findings.push({ payload: m[1].trim(), context: "reflected" });
  }
  return findings;
}

export function summarizeXsstrikeResult(result: ToolRunResult): ToolRunResult {
  const findings = parseXsstrikeOutput(result.rawOutput);
  return {
    ...result,
    structuredData: { ...result.structuredData, findings, vulnerable: findings.length > 0 },
  };
}
