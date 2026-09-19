/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * theHarvester adapter — passive OSINT (emails/hosts) against an authorized
 * domain, sourced from public data (certificate transparency, search engines).
 * Never sends a request to the target's own infrastructure.
 *
 * LOW risk: same posture as subfinder — passive by construction, so it can
 * run automatically once the target is confirmed in-scope.
 *
 * NOTE: there is no single canonical "official" theHarvester Docker image.
 * THEHARVESTER_IMAGE must be pinned to an image you've built/reviewed before
 * production use.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";
import { DEFAULT_RESOURCE_LIMITS } from "./types";
import { extractHost, isIPv4 } from "../core/scope";

export const THEHARVESTER_TOOL_ID = "theharvester";
export const theHarvesterImage = () =>
  process.env.THEHARVESTER_IMAGE || "theharvester/theharvester:latest";

/** Domain shape only — excludes a dotted-quad IP, since theHarvester enumerates a domain, not a host. */
const DOMAIN_RE =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$/;

export const TheHarvesterParamsSchema = z.object({
  source: z.enum(["crtsh", "hackertarget", "duckduckgo", "bing"]).optional().default("crtsh"),
  limit: z.number().int().min(1).max(500).optional().default(200),
});

export type TheHarvesterParams = z.infer<typeof TheHarvesterParamsSchema>;

export function buildTheHarvesterRequest(target: string, rawParams: unknown): ToolRunRequest {
  const domain = extractHost(target).toLowerCase();
  if (isIPv4(domain) || !DOMAIN_RE.test(domain)) {
    throw new Error(
      `theHarvester requires a registrable domain (got "${target}"). IPs and URLs with paths are not valid input.`,
    );
  }
  const params = TheHarvesterParamsSchema.parse(rawParams ?? {});
  const args = ["-d", domain, "-b", params.source, "-l", String(params.limit)];
  return {
    toolId: THEHARVESTER_TOOL_ID,
    target: domain,
    args,
    image: theHarvesterImage(),
    params: { ...params },
  };
}

export interface HarvesterFindings {
  emails: string[];
  hosts: string[];
}

export function parseTheHarvesterOutput(raw: string): HarvesterFindings {
  const emails = Array.from(new Set(raw.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? []));
  const hosts = Array.from(new Set(raw.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi) ?? [])).filter(
    (h) => !emails.some((e) => e.toLowerCase().endsWith(h.toLowerCase())),
  );
  return { emails, hosts };
}

export function summarizeTheHarvesterResult(result: ToolRunResult): ToolRunResult {
  const findings = parseTheHarvesterOutput(result.rawOutput);
  return {
    ...result,
    structuredData: {
      ...result.structuredData,
      ...findings,
      emailCount: findings.emails.length,
      hostCount: findings.hosts.length,
    },
  };
}

export const theHarvesterDescriptor: ToolDescriptor = {
  id: THEHARVESTER_TOOL_ID,
  name: "theHarvester Passive OSINT",
  version: "1.0.0",
  description:
    "Passive email/host reconnaissance for an authorized domain, sourced from " +
    "public data only. Never contacts the target's own infrastructure.",
  capabilities: ["osint", "email-enumeration", "asset-discovery"],
  inputSchema: TheHarvesterParamsSchema,
  outputSchemaHint: '{ emails: string[], hosts: string[], emailCount, hostCount }',
  permissions: ["network:passive-recon"],
  riskLevel: "LOW",
  timeoutMs: 120_000,
  resourceLimits: { ...DEFAULT_RESOURCE_LIMITS, memoryMb: 256 },
  sandboxRequired: true,
  needsNetwork: true,
  targetKind: "network",
  filesystemAccess: "none",
  get image() {
    return theHarvesterImage();
  },
};

export const theHarvesterAdapter: ToolAdapter = {
  descriptor: theHarvesterDescriptor,
  build: buildTheHarvesterRequest,
  parse: summarizeTheHarvesterResult,
};
