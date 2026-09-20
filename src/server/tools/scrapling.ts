/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Scrapling adapter — stealthy web fetching for technology fingerprinting /
 * attack-surface mapping against an authorized web target
 * (https://github.com/D4Vinci/Scrapling), via its official Docker image.
 *
 * STATUS: DECLARED ONLY, not registered in the ADAPTERS array (see
 * tools/registry.ts). Every other real adapter in this platform (nmap,
 * nuclei, semgrep, trivy, zap, ...) captures output through the underlying
 * tool's native STDOUT mode (e.g. `--json`), because the sandbox executor
 * (sandbox/docker.ts) only captures container logs — it does not read files
 * back out of the container.
 *
 * Scrapling's `extract` CLI has no documented stdout mode: `scrapling
 * extract get '<url>' <output-file>` writes to a file, and its format
 * (markdown/text/html) is selected by that file's extension. This file
 * targets `/dev/stdout` as the output path — writing there should still land
 * on the captured stream regardless of what format Scrapling picks for an
 * unrecognized extension, but that is an assumption about Scrapling's own
 * internal branching, not something verified here: this environment has no
 * Docker daemon to actually run the image and confirm it. Promote this to
 * `ADAPTERS` in registry.ts only after a real container run confirms the
 * output actually appears on stdout in a parseable format.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolDescriptor } from "./types";
import { DEFAULT_RESOURCE_LIMITS } from "./types";

export const SCRAPLING_TOOL_ID = "scrapling";
export const scraplingImage = () => process.env.SCRAPLING_IMAGE || "ghcr.io/d4vinci/scrapling:latest";

/** Chrome/Firefox/Edge/Safari only — not a free-form string an attacker could
 *  turn into flag injection via a chained `--` argument. */
export const ALLOWED_IMPERSONATIONS = ["chrome", "firefox", "safari", "edge"] as const;

export const ScraplingParamsSchema = z.object({
  /** get: plain HTTP fetch. fetch: headless browser. stealthy-fetch: anti-bot/anti-detection fetch. */
  mode: z.enum(["get", "fetch", "stealthy-fetch"]).optional().default("get"),
  cssSelector: z.string().max(300).optional(),
  impersonate: z.enum(ALLOWED_IMPERSONATIONS).optional(),
  /** Only meaningful with mode: "stealthy-fetch". Bypasses Cloudflare's Turnstile
   *  challenge — more intrusive than a plain fetch, so it is opt-in, never default. */
  solveCloudflare: z.boolean().optional().default(false),
});

export type ScraplingParams = z.infer<typeof ScraplingParamsSchema>;

export function buildScraplingRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = ScraplingParamsSchema.parse(rawParams ?? {});
  const args = ["extract", params.mode, target, "/dev/stdout"];
  if (params.cssSelector) args.push("--css-selector", params.cssSelector);
  if (params.impersonate) args.push("--impersonate", params.impersonate);
  if (params.mode === "stealthy-fetch" && params.solveCloudflare) args.push("--solve-cloudflare");
  return {
    toolId: SCRAPLING_TOOL_ID,
    target,
    args,
    image: scraplingImage(),
    params: { ...params },
  };
}

export interface ScraplingFingerprint {
  /** Best-effort signature matches. Detection, not confirmation — same
   *  posture as a nuclei hit: these are hints for the Validation stage. */
  technologies: string[];
  title: string | null;
  contentLength: number;
}

const TECH_SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: "WordPress", pattern: /wp-content|wp-includes|generator"\s+content="WordPress/i },
  { name: "jQuery", pattern: /jquery[.-]([\d.]+)?\.js/i },
  { name: "React", pattern: /data-reactroot|__NEXT_DATA__|react-dom/i },
  { name: "Drupal", pattern: /sites\/default\/files|generator"\s+content="Drupal/i },
  { name: "Nginx", pattern: /server:\s*nginx/i },
  { name: "Apache", pattern: /server:\s*apache/i },
  { name: "PHP", pattern: /x-powered-by:\s*php/i },
];

/** Parse fetched HTML/text for a title and best-effort technology hints. */
export function parseScraplingOutput(raw: string): ScraplingFingerprint {
  const titleMatch = raw.match(/<title[^>]*>([^<]*)<\/title>/i);
  const technologies = TECH_SIGNATURES.filter((sig) => sig.pattern.test(raw)).map((sig) => sig.name);
  return {
    technologies,
    title: titleMatch ? titleMatch[1].trim() : null,
    contentLength: raw.length,
  };
}

export function summarizeScraplingResult(result: ToolRunResult): ToolRunResult {
  const fingerprint = parseScraplingOutput(result.rawOutput);
  return {
    ...result,
    structuredData: { ...result.structuredData, ...fingerprint },
  };
}

export const scraplingDescriptor: ToolDescriptor = {
  id: SCRAPLING_TOOL_ID,
  name: "Scrapling Stealthy Web Fetcher",
  version: "0.0.0-unverified",
  description:
    "Stealthy web fetching (anti-bot bypass, headless browser, Cloudflare " +
    "Turnstile bypass) against an authorized target, for technology " +
    "fingerprinting. DECLARED ONLY: stdout output capture is unverified " +
    "against a real container — see this file's module doc.",
  capabilities: ["web-fetch", "tech-fingerprint", "stealthy-fetch"],
  inputSchema: ScraplingParamsSchema,
  outputSchemaHint: '{ technologies: string[], title: string|null, contentLength: number }',
  permissions: ["network:scan", "web:probe"],
  riskLevel: "MEDIUM",
  timeoutMs: 120_000,
  resourceLimits: { ...DEFAULT_RESOURCE_LIMITS, memoryMb: 1024 },
  sandboxRequired: true,
  needsNetwork: true,
  targetKind: "network",
  filesystemAccess: "none",
  get image() {
    return scraplingImage();
  },
};
