/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * nuclei adapter — template-driven vulnerability detection against an
 * authorized web target.
 *
 * Safety posture baked into the argument vector:
 *   - template tags are validated against an allowlist, so a caller cannot
 *     select intrusive/DoS template groups through free-form input;
 *   - rate limiting and concurrency are capped;
 *   - `-jsonl` output is parsed structurally, never scraped.
 *
 * A nuclei hit is a DETECTION, not a confirmed vulnerability: every parsed
 * result is emitted with `validated: false` for the validation stage to judge.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";
import { DEFAULT_RESOURCE_LIMITS } from "./types";

export const NUCLEI_TOOL_ID = "nuclei";
export const nucleiImage = () =>
  process.env.NUCLEI_IMAGE || "projectdiscovery/nuclei:latest";

/** Non-intrusive template groups only. `dos`, `fuzzing` and `intrusive` are
 *  deliberately absent and cannot be requested. */
export const ALLOWED_TAGS = [
  "cve",
  "misconfig",
  "exposure",
  "tech",
  "default-login",
  "ssl",
  "takeover",
] as const;

export const ALLOWED_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

export const NucleiParamsSchema = z.object({
  tags: z
    .array(z.enum(ALLOWED_TAGS))
    .min(1)
    .max(ALLOWED_TAGS.length)
    .optional()
    .default(["cve", "misconfig", "exposure"]),
  severity: z
    .array(z.enum(ALLOWED_SEVERITIES))
    .min(1)
    .optional()
    .default(["low", "medium", "high", "critical"]),
  /** Requests per second, hard-capped so a scan cannot become a flood. */
  rateLimit: z.number().int().min(1).max(50).optional().default(20),
  concurrency: z.number().int().min(1).max(25).optional().default(10),
  timeoutSeconds: z.number().int().min(5).max(600).optional().default(300),
});

export type NucleiParams = z.infer<typeof NucleiParamsSchema>;

export function buildNucleiRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = NucleiParamsSchema.parse(rawParams ?? {});
  const args = [
    "-u", target,
    "-jsonl",
    "-silent",
    "-no-interactsh", // no out-of-band callbacks from a sandboxed lab run
    "-disable-update-check",
    "-tags", params.tags.join(","),
    "-severity", params.severity.join(","),
    "-rate-limit", String(params.rateLimit),
    "-concurrency", String(params.concurrency),
    "-timeout", String(Math.min(params.timeoutSeconds, 60)),
  ];
  return {
    toolId: NUCLEI_TOOL_ID,
    target,
    args,
    image: nucleiImage(),
    params: { ...params },
  };
}

export interface NucleiDetection {
  templateId: string;
  name: string;
  severity: string;
  matchedAt: string;
  type: string;
  description?: string;
  cve?: string[];
  cwe?: string[];
  /** Always false here: detection is not validation (§18). */
  validated: false;
}

function asStringArray(v: unknown): string[] | undefined {
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : undefined;
}

/** Parse nuclei's JSONL output into detections. Malformed lines are skipped. */
export function parseNucleiOutput(raw: string): NucleiDetection[] {
  const out: NucleiDetection[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      continue;
    }
    const templateId = obj["template-id"] ?? obj.templateID ?? obj.templateId;
    if (typeof templateId !== "string") continue;
    const info = (obj.info ?? {}) as Record<string, unknown>;
    const classification = (info.classification ?? {}) as Record<string, unknown>;
    out.push({
      templateId,
      name: typeof info.name === "string" ? info.name : templateId,
      severity: typeof info.severity === "string" ? info.severity.toLowerCase() : "unknown",
      matchedAt: typeof obj["matched-at"] === "string" ? (obj["matched-at"] as string) : "",
      type: typeof obj.type === "string" ? obj.type : "http",
      description: typeof info.description === "string" ? info.description : undefined,
      cve: asStringArray(classification["cve-id"]),
      cwe: asStringArray(classification["cwe-id"]),
      validated: false,
    });
  }
  return out;
}

export function summarizeNucleiResult(result: ToolRunResult): ToolRunResult {
  const detections = parseNucleiOutput(result.rawOutput);
  const bySeverity: Record<string, number> = {};
  for (const d of detections) bySeverity[d.severity] = (bySeverity[d.severity] ?? 0) + 1;
  return {
    ...result,
    structuredData: {
      ...result.structuredData,
      detections,
      detectionCount: detections.length,
      bySeverity,
    },
  };
}

export const nucleiDescriptor: ToolDescriptor = {
  id: NUCLEI_TOOL_ID,
  name: "Nuclei Vulnerability Engine",
  version: "1.0.0",
  description:
    "Template-driven vulnerability detection against an authorized web target. " +
    "Non-intrusive template groups only; rate limit and concurrency are capped.",
  capabilities: ["template-scanning", "vulnerability-detection"],
  inputSchema: NucleiParamsSchema,
  outputSchemaHint:
    '{ detections: [{ templateId, name, severity, matchedAt, cve, cwe, validated:false }], detectionCount, bySeverity }',
  permissions: ["network:scan", "web:probe"],
  riskLevel: "MEDIUM",
  timeoutMs: 300_000,
  resourceLimits: { ...DEFAULT_RESOURCE_LIMITS, memoryMb: 1024 },
  sandboxRequired: true,
  needsNetwork: true,
  get image() {
    return nucleiImage();
  },
};

export const nucleiAdapter: ToolAdapter = {
  descriptor: nucleiDescriptor,
  build: buildNucleiRequest,
  parse: summarizeNucleiResult,
};
