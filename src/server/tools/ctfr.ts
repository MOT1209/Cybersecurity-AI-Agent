/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * ctfr tool adapter. Passive subdomain enumeration via certificate-transparency
 * logs (crt.sh) — never touches the target host directly.
 *
 * NOTE: there is no widely-known official Docker image for ctfr. CTFR_IMAGE
 * must be pinned to an image you've built/reviewed before production use.
 */

import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import { ToolInputError } from "./errors";

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/i;
const IPV4_LIKE_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function isBareDomain(value: string): boolean {
  return DOMAIN_RE.test(value) && !IPV4_LIKE_RE.test(value);
}

export const CTFR_TOOL_ID = "ctfr";
export const ctfrImage = () => process.env.CTFR_IMAGE || "ghcr.io/unapibageek/ctfr:latest";

/** ctfr enumerates a domain's CT-log subdomains — target must be a bare domain. */
export function buildCtfrRequest(target: string): ToolRunRequest {
  const domain = target.trim().toLowerCase();
  if (!isBareDomain(domain)) {
    throw new ToolInputError(`ctfr target must be a bare domain (e.g. "example.com"), got "${target}"`);
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
