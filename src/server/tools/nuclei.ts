/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * nuclei tool adapter. Template-based vulnerability scanner; runs against a
 * URL/host target and emits JSON Lines findings on stdout.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";

export const NucleiParamsSchema = z.object({
  severity: z
    .string()
    .regex(
      /^(critical|high|medium|low|info)(,(critical|high|medium|low|info))*$/,
      "severity must be a comma-separated list of critical,high,medium,low,info",
    )
    .optional()
    .default("critical,high,medium"),
  rateLimit: z.number().int().min(1).max(150).optional().default(50),
});

export type NucleiParams = z.infer<typeof NucleiParamsSchema>;

export const NUCLEI_TOOL_ID = "nuclei";
// Official image; verified to exist on Docker Hub as of the template's authoring.
export const nucleiImage = () => process.env.NUCLEI_IMAGE || "projectdiscovery/nuclei:latest";

export function buildNucleiRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = NucleiParamsSchema.parse(rawParams ?? {});
  const args = [
    "-u",
    target,
    "-severity",
    params.severity,
    "-rate-limit",
    String(params.rateLimit),
    "-jsonl",
    "-silent",
  ];
  return {
    toolId: NUCLEI_TOOL_ID,
    target,
    args,
    image: nucleiImage(),
    params: { ...params },
  };
}

export interface NucleiFinding {
  templateId: string;
  severity: string;
  matchedAt: string;
}

/** Parses nuclei's `-jsonl` output: one JSON object per finding per line. */
export function parseNucleiOutput(raw: string): NucleiFinding[] {
  const findings: NucleiFinding[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const obj = JSON.parse(trimmed);
      findings.push({
        templateId: obj["template-id"] ?? "unknown",
        severity: obj.info?.severity ?? "unknown",
        matchedAt: obj["matched-at"] ?? obj.host ?? "",
      });
    } catch {
      continue;
    }
  }
  return findings;
}

export function summarizeNucleiResult(result: ToolRunResult): ToolRunResult {
  const findings = parseNucleiOutput(result.rawOutput);
  return {
    ...result,
    structuredData: { ...result.structuredData, findings, findingCount: findings.length },
  };
}
