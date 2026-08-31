/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Semgrep adapter — static application security testing over code inside the
 * workspace root.
 *
 * The scanned tree is bind-mounted read-only and the container has no network,
 * so an untrusted repository cannot be modified and cannot phone home. Rule
 * configs are restricted to a curated allowlist of registry rulesets: a
 * free-form `--config` accepts a URL, which would be arbitrary remote rule
 * execution driven by caller input.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";

export const SEMGREP_TOOL_ID = "semgrep";
export const semgrepImage = () => process.env.SEMGREP_IMAGE || "semgrep/semgrep:latest";

/** Curated registry rulesets. A caller cannot supply a URL or local rule file. */
export const ALLOWED_RULESETS = [
  "p/owasp-top-ten",
  "p/security-audit",
  "p/secrets",
  "p/ci",
  "p/javascript",
  "p/typescript",
  "p/python",
  "p/golang",
  "p/java",
] as const;

export const SemgrepParamsSchema = z.object({
  ruleset: z.enum(ALLOWED_RULESETS).optional().default("p/owasp-top-ten"),
  /** Skip vendored/minified artifacts: the classic OOM source. */
  excludeMinified: z.boolean().optional().default(true),
  maxTargetBytes: z.number().int().min(10_000).max(20_000_000).optional().default(2_000_000),
  timeoutSeconds: z.number().int().min(10).max(900).optional().default(300),
});

export type SemgrepParams = z.infer<typeof SemgrepParamsSchema>;

/**
 * `target` is the container-side path produced by the workspace resolver, so it
 * is already contained. It is passed as the final positional argument.
 */
export function buildSemgrepRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = SemgrepParamsSchema.parse(rawParams ?? {});
  const args = [
    "semgrep", "scan",
    "--config", params.ruleset,
    "--json",
    "--quiet",
    "--metrics=off",           // no telemetry from a security tool run
    "--disable-version-check",
    "--timeout", String(params.timeoutSeconds),
    "--max-target-bytes", String(params.maxTargetBytes),
  ];
  if (params.excludeMinified) {
    args.push("--exclude", "*.min.js", "--exclude", "*.map", "--exclude", "node_modules");
  }
  args.push(target);
  return {
    toolId: SEMGREP_TOOL_ID,
    target,
    args,
    image: semgrepImage(),
    params: { ...params },
  };
}

export interface SemgrepFinding {
  ruleId: string;
  message: string;
  severity: string;
  path: string;
  startLine: number;
  endLine: number;
  cwe: string[];
  owasp: string[];
  /** Detection only — confirmation is the validation stage's job (§18). */
  validated: false;
}

const SEVERITY_MAP: Record<string, string> = { ERROR: "high", WARNING: "medium", INFO: "low" };

/** Parse semgrep's `--json` document. Returns [] for unparseable output. */
export function parseSemgrepOutput(raw: string): SemgrepFinding[] {
  const start = raw.indexOf("{");
  if (start < 0) return [];
  let doc: { results?: unknown };
  try {
    doc = JSON.parse(raw.slice(start)) as { results?: unknown };
  } catch {
    return [];
  }
  if (!Array.isArray(doc.results)) return [];

  const out: SemgrepFinding[] = [];
  for (const r of doc.results as Record<string, unknown>[]) {
    const check = r.check_id;
    if (typeof check !== "string") continue;
    const extra = (r.extra ?? {}) as Record<string, unknown>;
    const meta = (extra.metadata ?? {}) as Record<string, unknown>;
    const start_ = (r.start ?? {}) as Record<string, unknown>;
    const end_ = (r.end ?? {}) as Record<string, unknown>;
    const toArr = (v: unknown): string[] =>
      Array.isArray(v)
        ? v.filter((x): x is string => typeof x === "string")
        : typeof v === "string"
          ? [v]
          : [];
    out.push({
      ruleId: check,
      message: typeof extra.message === "string" ? extra.message : check,
      severity: SEVERITY_MAP[String(extra.severity ?? "").toUpperCase()] ?? "medium",
      path: typeof r.path === "string" ? r.path : "",
      startLine: typeof start_.line === "number" ? start_.line : 0,
      endLine: typeof end_.line === "number" ? end_.line : 0,
      cwe: toArr(meta.cwe),
      owasp: toArr(meta.owasp),
      validated: false,
    });
  }
  return out;
}

export function summarizeSemgrepResult(result: ToolRunResult): ToolRunResult {
  const findings = parseSemgrepOutput(result.rawOutput);
  const bySeverity: Record<string, number> = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  return {
    ...result,
    structuredData: { ...result.structuredData, findings, findingCount: findings.length, bySeverity },
  };
}

export const semgrepDescriptor: ToolDescriptor = {
  id: SEMGREP_TOOL_ID,
  name: "Semgrep SAST Code Engine",
  version: "1.0.0",
  description:
    "Static analysis over code in the workspace root. Runs with no network and " +
    "a read-only mount; rulesets are restricted to a curated allowlist.",
  capabilities: ["static-analysis", "secret-detection"],
  inputSchema: SemgrepParamsSchema,
  outputSchemaHint:
    '{ findings: [{ ruleId, message, severity, path, startLine, cwe, owasp, validated:false }], findingCount, bySeverity }',
  permissions: ["workspace:read"],
  riskLevel: "LOW",
  timeoutMs: 600_000,
  resourceLimits: { cpus: 2, memoryMb: 2048, pids: 512 },
  sandboxRequired: true,
  needsNetwork: false,
  targetKind: "filesystem",
  filesystemAccess: "workspace-ro",
  get image() {
    return semgrepImage();
  },
};

export const semgrepAdapter: ToolAdapter = {
  descriptor: semgrepDescriptor,
  build: buildSemgrepRequest,
  parse: summarizeSemgrepResult,
};
