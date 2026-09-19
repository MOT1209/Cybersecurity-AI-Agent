/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Skill security scanner (§7 of the manifest lifecycle: discover → load →
 * validate → SCAN → register). Bounded and deterministic — this is not
 * static analysis of arbitrary code, it is a fixed set of checks against the
 * manifest's own declared metadata, run before a skill is ever marked
 * executable.
 */

import type { SkillManifest } from "./manifest";
import { hasAdapter, isToolRegistered } from "../tools/registry";
import { isCriticalToolEnabled } from "../security/policy";

/** Coarse permission tags a skill may declare. Anything outside this list
 *  fails the scan — an unrecognized permission is denied, not ignored. */
export const ALLOWED_SKILL_PERMISSIONS = [
  "network:scan",
  "network:passive-recon",
  "web:probe",
  "web:test",
  "filesystem:workspace-read",
] as const;

export interface SkillScanResult {
  passed: boolean;
  /** One entry per check, whether it passed or failed — an audit trail, not just a verdict. */
  findings: { check: string; passed: boolean; detail: string }[];
}

/**
 * Run the fixed scan checks against a manifest. Does not touch the
 * filesystem or network — pure evaluation of already-loaded, already
 * schema-validated data.
 */
export function scanSkillManifest(
  manifest: SkillManifest,
  registeredSkillIds: ReadonlySet<string>,
): SkillScanResult {
  const findings: SkillScanResult["findings"] = [];

  // 1. Every required tool must be REGISTERED AND IMPLEMENTED (a real
  //    adapter, not just a declared descriptor). A skill that leans on a
  //    tool the platform can't actually run is not executable, full stop.
  const missingTools = manifest.requiredTools.filter((t) => !isToolRegistered(t) || !hasAdapter(t));
  findings.push({
    check: "required-tools-implemented",
    passed: missingTools.length === 0,
    detail: missingTools.length === 0
      ? "Every required tool has a registered, real adapter."
      : `Missing or unimplemented tool adapter(s): ${missingTools.join(", ")}.`,
  });

  // 2. The platform has no MCP layer (docs/architecture/current-state.md §4).
  //    A skill naming an MCP requirement can never be executable — this is
  //    truthful by construction, not a gap to silently paper over.
  findings.push({
    check: "no-unavailable-mcp-dependency",
    passed: manifest.requiredMcp.length === 0,
    detail: manifest.requiredMcp.length === 0
      ? "Skill declares no MCP server requirement."
      : `Skill requires MCP server(s) [${manifest.requiredMcp.join(", ")}], but no MCP platform exists yet — NOT_AVAILABLE.`,
  });

  // 3. Permissions must be a subset of the fixed allowlist.
  const unknownPermissions = manifest.permissions.filter(
    (p) => !(ALLOWED_SKILL_PERMISSIONS as readonly string[]).includes(p),
  );
  findings.push({
    check: "permissions-allowlisted",
    passed: unknownPermissions.length === 0,
    detail: unknownPermissions.length === 0
      ? "All declared permissions are on the platform allowlist."
      : `Unrecognized permission(s), denied: ${unknownPermissions.join(", ")}.`,
  });

  // 4. Dependencies must already be registered — no forward references to a
  //    skill that may or may not ever exist.
  const missingDeps = manifest.dependencies.filter((d) => !registeredSkillIds.has(d));
  findings.push({
    check: "dependencies-registered",
    passed: missingDeps.length === 0,
    detail: missingDeps.length === 0
      ? "All declared dependencies are registered skills."
      : `Unregistered dependency skill(s): ${missingDeps.join(", ")}.`,
  });

  // 5. CRITICAL-risk skills are disabled by default, same policy as CRITICAL
  //    tools — an operator must explicitly opt in per skill id.
  const criticalDisabled = manifest.riskLevel === "CRITICAL" && !isCriticalToolEnabled(manifest.id);
  findings.push({
    check: "critical-risk-enabled",
    passed: !criticalDisabled,
    detail: manifest.riskLevel !== "CRITICAL"
      ? `Risk level ${manifest.riskLevel} does not require explicit enablement.`
      : criticalDisabled
        ? `CRITICAL-risk skill "${manifest.id}" is disabled by default. Enable via ENABLE_CRITICAL_TOOLS.`
        : `CRITICAL-risk skill "${manifest.id}" is explicitly enabled.`,
  });

  // 6. A skill's own declared maxRiskLevel cannot be lower than its riskLevel
  //    — that would let it claim a tighter security policy than its actual
  //    risk while still running at the higher risk.
  const riskOrder = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 } as const;
  const policyConsistent = riskOrder[manifest.securityPolicy.maxRiskLevel] >= riskOrder[manifest.riskLevel];
  findings.push({
    check: "security-policy-consistent",
    passed: policyConsistent,
    detail: policyConsistent
      ? "securityPolicy.maxRiskLevel is consistent with the skill's own riskLevel."
      : `securityPolicy.maxRiskLevel (${manifest.securityPolicy.maxRiskLevel}) is lower than the skill's own riskLevel (${manifest.riskLevel}) — inconsistent, denied.`,
  });

  return { passed: findings.every((f) => f.passed), findings };
}
