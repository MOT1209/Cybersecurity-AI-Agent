/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * theHarvester tool adapter. Passive OSINT (emails/hosts) against a bare
 * domain — never touches the target host directly, so it carries lower risk
 * than an active scanner even against a live production domain.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import { ToolInputError } from "./errors";

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/i;
const IPV4_LIKE_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function isBareDomain(value: string): boolean {
  return DOMAIN_RE.test(value) && !IPV4_LIKE_RE.test(value);
}

export const TheHarvesterParamsSchema = z.object({
  source: z.enum(["crtsh", "hackertarget", "duckduckgo", "bing"]).optional().default("crtsh"),
  limit: z.number().int().min(1).max(500).optional().default(200),
});

export type TheHarvesterParams = z.infer<typeof TheHarvesterParamsSchema>;

export const THEHARVESTER_TOOL_ID = "theharvester";
// No single canonical official image — pin and verify one before production use.
export const theHarvesterImage = () => process.env.THEHARVESTER_IMAGE || "theharvester/theharvester:latest";

/** theHarvester enumerates a domain, not an IP/URL — target must be a bare domain. */
export function buildTheHarvesterRequest(target: string, rawParams: unknown): ToolRunRequest {
  const domain = target.trim().toLowerCase();
  if (!isBareDomain(domain)) {
    throw new ToolInputError(`theHarvester target must be a bare domain (e.g. "example.com"), got "${target}"`);
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
