/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Trivy adapter — filesystem, dependency and container-image scanning.
 *
 * Scope note: `fs` and `repo` scan a read-only mount of the workspace and run
 * with no network. `image` is deliberately NOT offered here — scanning a remote
 * image requires registry egress and an image reference is caller-controlled,
 * which is a materially different trust boundary. It belongs behind its own
 * descriptor and approval, not smuggled in as a mode flag.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";

export const TRIVY_TOOL_ID = "trivy";
export const trivyImage = () => process.env.TRIVY_IMAGE || "aquasec/trivy:latest";

export const TrivyParamsSchema = z.object({
  scanType: z.enum(["fs", "repo"]).optional().default("fs"),
  severity: z
    .array(z.enum(["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]))
    .min(1)
    .optional()
    .default(["HIGH", "CRITICAL"]),
  scanners: z
    .array(z.enum(["vuln", "misconfig", "secret", "license"]))
    .min(1)
    .optional()
    .default(["vuln", "secret"]),
  ignoreUnfixed: z.boolean().optional().default(false),
  timeoutSeconds: z.number().int().min(10).max(900).optional().default(300),
});

export type TrivyParams = z.infer<typeof TrivyParamsSchema>;

export function buildTrivyRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = TrivyParamsSchema.parse(rawParams ?? {});
  const args = [
    params.scanType,
    "--format", "json",
    "--quiet",
    "--offline-scan",           // never resolve dependencies over the network
    "--skip-db-update",         // the DB ships in the image; no egress at runtime
    "--severity", params.severity.join(","),
    "--scanners", params.scanners.join(","),
    "--timeout", `${params.timeoutSeconds}s`,
  ];
  if (params.ignoreUnfixed) args.push("--ignore-unfixed");
  args.push(target);
  return {
    toolId: TRIVY_TOOL_ID,
    target,
    args,
    image: trivyImage(),
    params: { ...params },
  };
}

export interface TrivyFinding {
  id: string;
  kind: "vulnerability" | "secret" | "misconfiguration";
  title: string;
  severity: string;
  target: string;
  pkgName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  /** Detection only — confirmation is the validation stage's job (§18). */
  validated: false;
}

/** Parse trivy's `--format json` document. Returns [] for unparseable output. */
export function parseTrivyOutput(raw: string): TrivyFinding[] {
  const start = raw.indexOf("{");
  if (start < 0) return [];
  let doc: { Results?: unknown };
  try {
    doc = JSON.parse(raw.slice(start)) as { Results?: unknown };
  } catch {
    return [];
  }
  if (!Array.isArray(doc.Results)) return [];

  const out: TrivyFinding[] = [];
  for (const r of doc.Results as Record<string, unknown>[]) {
    const where = typeof r.Target === "string" ? r.Target : "";

    for (const v of (Array.isArray(r.Vulnerabilities) ? r.Vulnerabilities : []) as Record<string, unknown>[]) {
      if (typeof v.VulnerabilityID !== "string") continue;
      out.push({
        id: v.VulnerabilityID,
        kind: "vulnerability",
        title: typeof v.Title === "string" ? v.Title : v.VulnerabilityID,
        severity: String(v.Severity ?? "UNKNOWN").toLowerCase(),
        target: where,
        pkgName: typeof v.PkgName === "string" ? v.PkgName : undefined,
        installedVersion: typeof v.InstalledVersion === "string" ? v.InstalledVersion : undefined,
        fixedVersion: typeof v.FixedVersion === "string" ? v.FixedVersion : undefined,
        validated: false,
      });
    }

    for (const s of (Array.isArray(r.Secrets) ? r.Secrets : []) as Record<string, unknown>[]) {
      if (typeof s.RuleID !== "string") continue;
      out.push({
        id: s.RuleID,
        kind: "secret",
        // The matched value is deliberately not carried into structured output.
        title: typeof s.Title === "string" ? s.Title : s.RuleID,
        severity: String(s.Severity ?? "UNKNOWN").toLowerCase(),
        target: where,
        validated: false,
      });
    }

    for (const m of (Array.isArray(r.Misconfigurations) ? r.Misconfigurations : []) as Record<string, unknown>[]) {
      if (typeof m.ID !== "string") continue;
      out.push({
        id: m.ID,
        kind: "misconfiguration",
        title: typeof m.Title === "string" ? m.Title : m.ID,
        severity: String(m.Severity ?? "UNKNOWN").toLowerCase(),
        target: where,
        validated: false,
      });
    }
  }
  return out;
}

export function summarizeTrivyResult(result: ToolRunResult): ToolRunResult {
  const findings = parseTrivyOutput(result.rawOutput);
  const bySeverity: Record<string, number> = {};
  const byKind: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byKind[f.kind] = (byKind[f.kind] ?? 0) + 1;
  }
  return {
    ...result,
    structuredData: { ...result.structuredData, findings, findingCount: findings.length, bySeverity, byKind },
  };
}

export const trivyDescriptor: ToolDescriptor = {
  id: TRIVY_TOOL_ID,
  name: "Trivy Filesystem & Dependency Scanner",
  version: "1.0.0",
  description:
    "Vulnerability, secret and misconfiguration scanning over the workspace. " +
    "Runs fully offline with a read-only mount and no network.",
  capabilities: ["dependency-scan", "fs-scan", "secret-detection", "misconfig-scan"],
  inputSchema: TrivyParamsSchema,
  outputSchemaHint:
    '{ findings: [{ id, kind, title, severity, target, pkgName, fixedVersion, validated:false }], findingCount, bySeverity, byKind }',
  permissions: ["workspace:read"],
  riskLevel: "LOW",
  timeoutMs: 600_000,
  resourceLimits: { cpus: 2, memoryMb: 2048, pids: 512 },
  sandboxRequired: true,
  needsNetwork: false,
  targetKind: "filesystem",
  filesystemAccess: "workspace-ro",
  get image() {
    return trivyImage();
  },
};

export const trivyAdapter: ToolAdapter = {
  descriptor: trivyDescriptor,
  build: buildTrivyRequest,
  parse: summarizeTrivyResult,
};
