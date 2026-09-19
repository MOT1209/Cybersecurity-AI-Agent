/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * ctfr adapter — passive subdomain enumeration via certificate-transparency
 * logs (crt.sh). Queries a third-party log, never the target's own
 * infrastructure, so it carries the same LOW-risk posture as subfinder.
 *
 * NOTE: there is no widely-known official Docker image for ctfr. CTFR_IMAGE
 * must be pinned to an image you've built/reviewed before production use.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";
import { DEFAULT_RESOURCE_LIMITS } from "./types";
import { extractHost, isIPv4 } from "../core/scope";

/** ctfr takes no tunable params — declared for registry introspection only. */
export const CtfrParamsSchema = z.object({}).passthrough();

export const CTFR_TOOL_ID = "ctfr";
export const ctfrImage = () => process.env.CTFR_IMAGE || "ghcr.io/unapibageek/ctfr:latest";

const DOMAIN_RE =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$/;

/** ctfr takes no tunable params — it queries one certificate-transparency source by domain. */
export function buildCtfrRequest(target: string): ToolRunRequest {
  const domain = extractHost(target).toLowerCase();
  if (isIPv4(domain) || !DOMAIN_RE.test(domain)) {
    throw new Error(
      `ctfr requires a registrable domain (got "${target}"). IPs and URLs with paths are not valid input.`,
    );
  }
  // "/dev/stdout" as the output path avoids relying on a writable filesystem
  // inside the read-only sandbox container — ctfr writes its results there.
  const args = ["-d", domain, "-o", "/dev/stdout"];
  return {
    toolId: CTFR_TOOL_ID,
    target: domain,
    args,
    image: ctfrImage(),
    params: {},
  };
}

export function parseCtfrOutput(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => /^(?:[a-z0-9*_-]+\.)+[a-z]{2,}$/i.test(l)),
    ),
  );
}

export function summarizeCtfrResult(result: ToolRunResult): ToolRunResult {
  const subdomains = parseCtfrOutput(result.rawOutput);
  return {
    ...result,
    structuredData: { ...result.structuredData, subdomains, subdomainCount: subdomains.length },
  };
}

export const ctfrDescriptor: ToolDescriptor = {
  id: CTFR_TOOL_ID,
  name: "ctfr Certificate-Transparency Enumeration",
  version: "1.0.0",
  description:
    "Passive subdomain enumeration via certificate-transparency logs (crt.sh). " +
    "Queries a public third-party log only; never contacts the target directly.",
  capabilities: ["subdomain-enumeration", "osint"],
  inputSchema: CtfrParamsSchema,
  outputSchemaHint: '{ subdomains: string[], subdomainCount }',
  permissions: ["network:passive-recon"],
  riskLevel: "LOW",
  timeoutMs: 60_000,
  resourceLimits: { ...DEFAULT_RESOURCE_LIMITS, memoryMb: 256 },
  sandboxRequired: true,
  needsNetwork: true,
  targetKind: "network",
  filesystemAccess: "none",
  get image() {
    return ctfrImage();
  },
};

export const ctfrAdapter: ToolAdapter = {
  descriptor: ctfrDescriptor,
  build: buildCtfrRequest,
  parse: summarizeCtfrResult,
};
