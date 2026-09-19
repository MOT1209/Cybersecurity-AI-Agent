/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * wfuzz tool adapter. Web fuzzer — substitutes wordlist entries into a "FUZZ"
 * placeholder in the target URL.
 *
 * NOTE: WFUZZ_IMAGE and the wordlist paths below assume a specific image
 * layout (Kali-style wordlist tree). There is no single canonical "official"
 * wfuzz image — pin and verify one before production use.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import { ToolInputError } from "./errors";

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

export const WFUZZ_TOOL_ID = "wfuzz";
export const wfuzzImage = () => process.env.WFUZZ_IMAGE || "wfuzz/wfuzz:latest";

/** `target` must contain the literal "FUZZ" placeholder wfuzz substitutes. */
export function buildWfuzzRequest(target: string, rawParams: unknown): ToolRunRequest {
  if (!target.includes("FUZZ")) {
    throw new ToolInputError('wfuzz target must contain a "FUZZ" placeholder, e.g. "http://host/FUZZ"');
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
    if (m) {
      hits.push({ id: Number(m[1]), statusCode: Number(m[2]), payload: m[3] });
    }
  }
  return hits;
}

export function summarizeWfuzzResult(result: ToolRunResult): ToolRunResult {
  const hits = parseWfuzzOutput(result.rawOutput);
  return { ...result, structuredData: { ...result.structuredData, hits, hitCount: hits.length } };
}
