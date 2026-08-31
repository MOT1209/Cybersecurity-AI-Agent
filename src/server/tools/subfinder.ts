/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * subfinder adapter — passive subdomain enumeration for an authorized domain.
 *
 * Passive by default (`-silent`, no brute force, no active resolution) so the
 * tool touches only public data sources unless the operator opts into active
 * resolution. Output is requested as JSONL and parsed structurally rather than
 * scraped from human-readable text.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";
import { DEFAULT_RESOURCE_LIMITS } from "./types";
import { extractHost, isIPv4 } from "../core/scope";

export const SUBFINDER_TOOL_ID = "subfinder";
export const subfinderImage = () =>
  process.env.SUBFINDER_IMAGE || "projectdiscovery/subfinder:latest";

export const SubfinderParamsSchema = z.object({
  /** Cap on results, so an enormous domain cannot exhaust the run. */
  maxResults: z.number().int().min(1).max(5000).optional().default(500),
  /** Resolve discovered hosts. Off by default — passive means passive. */
  activeResolution: z.boolean().optional().default(false),
  timeoutSeconds: z.number().int().min(5).max(300).optional().default(60),
});

export type SubfinderParams = z.infer<typeof SubfinderParamsSchema>;

/**
 * Domain shape only: no scheme, no path, no shell metacharacters, and an
 * alphabetic TLD — which also excludes a dotted-quad IP, since subdomain
 * enumeration of an IP is meaningless.
 */
const DOMAIN_RE =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$/;

export function buildSubfinderRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = SubfinderParamsSchema.parse(rawParams ?? {});
  const domain = extractHost(target);
  if (isIPv4(domain) || !DOMAIN_RE.test(domain)) {
    throw new Error(
      `subfinder requires a registrable domain (got "${target}"). IPs, URLs with paths and bare hostnames are not valid input.`,
    );
  }
  const args = [
    "-d", domain,
    "-silent",
    "-json",
    "-max-time", String(Math.ceil(params.timeoutSeconds / 60)),
  ];
  if (params.activeResolution) args.push("-active");
  return {
    toolId: SUBFINDER_TOOL_ID,
    target: domain,
    args,
    image: subfinderImage(),
    params: { ...params },
  };
}

export interface Subdomain {
  host: string;
  source?: string;
}

/**
 * Parse subfinder's JSONL output. Lines that are not valid JSON objects with a
 * `host` field are ignored rather than guessed at — a malformed line is not a
 * discovery.
 */
export function parseSubfinderOutput(raw: string, maxResults = 5000): Subdomain[] {
  const seen = new Set<string>();
  const out: Subdomain[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const rec = obj as { host?: unknown; source?: unknown };
    if (typeof rec.host !== "string" || !rec.host) continue;
    const host = rec.host.toLowerCase();
    if (seen.has(host)) continue;
    seen.add(host);
    out.push({ host, source: typeof rec.source === "string" ? rec.source : undefined });
    if (out.length >= maxResults) break;
  }
  return out;
}

export function summarizeSubfinderResult(result: ToolRunResult): ToolRunResult {
  const max = Number(result.structuredData?.params && (result.structuredData.params as SubfinderParams).maxResults) || 5000;
  const subdomains = parseSubfinderOutput(result.rawOutput, max);
  return {
    ...result,
    structuredData: {
      ...result.structuredData,
      subdomains,
      subdomainCount: subdomains.length,
    },
  };
}

export const subfinderDescriptor: ToolDescriptor = {
  id: SUBFINDER_TOOL_ID,
  name: "Subfinder Subdomain Recon",
  version: "1.0.0",
  description:
    "Passive subdomain enumeration for an authorized domain. Queries public " +
    "sources only; active resolution is opt-in.",
  capabilities: ["subdomain-enumeration", "asset-discovery"],
  inputSchema: SubfinderParamsSchema,
  outputSchemaHint: '{ subdomains: [{ host, source }], subdomainCount: number }',
  permissions: ["network:passive-recon"],
  riskLevel: "LOW",
  timeoutMs: 120_000,
  resourceLimits: { ...DEFAULT_RESOURCE_LIMITS, memoryMb: 256 },
  sandboxRequired: true,
  needsNetwork: true,
  get image() {
    return subfinderImage();
  },
};

export const subfinderAdapter: ToolAdapter = {
  descriptor: subfinderDescriptor,
  build: buildSubfinderRequest,
  parse: summarizeSubfinderResult,
};
