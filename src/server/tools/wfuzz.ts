/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * wfuzz adapter — web content/parameter fuzzing against an authorized target.
 * The target URL must contain a "FUZZ" placeholder that wfuzz substitutes
 * wordlist entries into; there is no default target-guessing.
 *
 * MEDIUM risk: this generates many requests against a live target (like
 * nuclei/subfinder), but never sends a crafted exploit payload — it is
 * enumeration, not exploitation. Wordlist choice is a fixed enum (never a
 * caller-supplied path) so the sandbox cannot be pointed at an arbitrary file.
 *
 * NOTE: there is no single canonical "official" wfuzz Docker image. WFUZZ_IMAGE
 * must be pinned to an image you've built/reviewed before production use.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";
import { DEFAULT_RESOURCE_LIMITS } from "./types";

export const WFUZZ_TOOL_ID = "wfuzz";
export const wfuzzImage = () => process.env.WFUZZ_IMAGE || "wfuzz/wfuzz:latest";

const WORDLISTS: Record<string, string> = {
  common: "/usr/share/wordlists/wfuzz/general/common.txt",
  medium: "/usr/share/wordlists/wfuzz/general/medium.txt",
  admin: "/usr/share/wordlists/wfuzz/general/admin-panels.txt",
};

export const WfuzzParamsSchema = z.object({
  wordlist: z.enum(["common", "medium", "admin"]).optional().default("common"),
  hideCodes: z
    .string()
    .regex(/^\d{3}(,\d{3})*$/, "hideCodes must be a comma-separated list of HTTP status codes")
    .optional(),
});

export type WfuzzParams = z.infer<typeof WfuzzParamsSchema>;

/** `target` must contain the literal "FUZZ" placeholder wfuzz substitutes. */
export function buildWfuzzRequest(target: string, rawParams: unknown): ToolRunRequest {
  if (!target.includes("FUZZ")) {
    throw new Error('wfuzz requires a "FUZZ" placeholder in the target, e.g. "http://host/FUZZ"');
  }
  const params = WfuzzParamsSchema.parse(rawParams ?? {});
  const args = ["-c", "-z", `file,${WORDLISTS[params.wordlist]}`];
  if (params.hideCodes) args.push("--hc", params.hideCodes);
  args.push(target);
  return {
    toolId: WFUZZ_TOOL_ID,
    target,
    args,
    image: wfuzzImage(),
    params: { ...params },
  };
}

export interface WfuzzHit {
  id: number;
  statusCode: number;
  payload: string;
}

/**
 * Best-effort parse of wfuzz's default table row format:
 * `000000123:  C=200    123 L   456 W    7890 Ch   "payload"`
 */
export function parseWfuzzOutput(raw: string): WfuzzHit[] {
  const hits: WfuzzHit[] = [];
  const re = /^(\d+):\s+C=(\d{3})\s+\d+\s+L\s+\d+\s+W\s+\d+\s+Ch\s+"(.*)"$/;
  for (const line of raw.split(/\r?\n/)) {
    const m = re.exec(line.trim());
    if (m) hits.push({ id: Number(m[1]), statusCode: Number(m[2]), payload: m[3] });
  }
  return hits;
}

export function summarizeWfuzzResult(result: ToolRunResult): ToolRunResult {
  const hits = parseWfuzzOutput(result.rawOutput);
  return { ...result, structuredData: { ...result.structuredData, hits, hitCount: hits.length } };
}

export const wfuzzDescriptor: ToolDescriptor = {
  id: WFUZZ_TOOL_ID,
  name: "wfuzz Content/Parameter Fuzzer",
  version: "1.0.0",
  description:
    "Web content and parameter fuzzing via wordlist substitution into a FUZZ " +
    "placeholder. Enumeration only — no crafted exploit payloads.",
  capabilities: ["content-discovery", "parameter-fuzzing"],
  inputSchema: WfuzzParamsSchema,
  outputSchemaHint: '{ hits: [{ id, statusCode, payload }], hitCount }',
  permissions: ["network:scan", "web:probe"],
  riskLevel: "MEDIUM",
  timeoutMs: 300_000,
  resourceLimits: { ...DEFAULT_RESOURCE_LIMITS, memoryMb: 512 },
  sandboxRequired: true,
  needsNetwork: true,
  targetKind: "network",
  filesystemAccess: "none",
  get image() {
    return wfuzzImage();
  },
};

export const wfuzzAdapter: ToolAdapter = {
  descriptor: wfuzzDescriptor,
  build: buildWfuzzRequest,
  parse: summarizeWfuzzResult,
};
