/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * XSStrike adapter — ACTIVE XSS testing against an authorized target. Injects
 * real payloads, so it is classified HIGH risk (the same tier as zap/sqlmap):
 * the risk policy engine requires explicit human approval for every run.
 *
 * NOTE: there is no official Docker Hub image for XSStrike. XSSTRIKE_IMAGE
 * must be pinned to an image you've built/reviewed before production use.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";

export const XSSTRIKE_TOOL_ID = "xsstrike";
export const xsstrikeImage = () => process.env.XSSTRIKE_IMAGE || "ghcr.io/s0md3v/xsstrike:latest";

export const XsstrikeParamsSchema = z.object({
  crawl: z.boolean().optional().default(false),
});

export type XsstrikeParams = z.infer<typeof XsstrikeParamsSchema>;

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

export const xsstrikeDescriptor: ToolDescriptor = {
  id: XSSTRIKE_TOOL_ID,
  name: "XSStrike XSS Tester",
  version: "1.0.0",
  description:
    "Active cross-site-scripting detection against an authorized target via " +
    "real reflected-payload injection. HIGH risk — every run requires human approval.",
  capabilities: ["web-scan", "xss"],
  inputSchema: XsstrikeParamsSchema,
  outputSchemaHint: '{ findings: [{ payload, context }], vulnerable: boolean }',
  permissions: ["network:scan", "web:test"],
  riskLevel: "HIGH",
  timeoutMs: 300_000,
  resourceLimits: { cpus: 1, memoryMb: 512, pids: 256 },
  sandboxRequired: true,
  needsNetwork: true,
  targetKind: "network",
  filesystemAccess: "none",
  get image() {
    return xsstrikeImage();
  },
};

export const xsstrikeAdapter: ToolAdapter = {
  descriptor: xsstrikeDescriptor,
  build: buildXsstrikeRequest,
  parse: summarizeXsstrikeResult,
};
