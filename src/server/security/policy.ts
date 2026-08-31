/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Risk policy engine (§14). The mapping from a tool's risk level to what the
 * platform is willing to do with it — expressed as data, so it cannot be talked
 * around by a model, a prompt, or a request body.
 *
 *   LOW      → may run automatically
 *   MEDIUM   → strict scope + full logging
 *   HIGH     → explicit human approval
 *   CRITICAL → disabled by default; lab-only, and only when explicitly enabled
 */

import type { RiskLevel } from "../tools/types";

export interface RiskPolicy {
  requiresApproval: boolean;
  requiresSandbox: boolean;
  /** Only permitted against a lab/private target. */
  labOnly: boolean;
  /** Disabled unless the operator explicitly enables it. */
  disabledByDefault: boolean;
}

export const RISK_POLICIES: Readonly<Record<RiskLevel, RiskPolicy>> = Object.freeze({
  LOW: { requiresApproval: false, requiresSandbox: true, labOnly: false, disabledByDefault: false },
  MEDIUM: { requiresApproval: false, requiresSandbox: true, labOnly: false, disabledByDefault: false },
  HIGH: { requiresApproval: true, requiresSandbox: true, labOnly: false, disabledByDefault: false },
  CRITICAL: { requiresApproval: true, requiresSandbox: true, labOnly: true, disabledByDefault: true },
});

export function policyFor(risk: RiskLevel): RiskPolicy {
  return RISK_POLICIES[risk] ?? RISK_POLICIES.CRITICAL; // unknown → most restrictive
}

/**
 * Operator allowlist for CRITICAL tools, e.g. ENABLE_CRITICAL_TOOLS="foo,bar".
 * Absent or empty means every CRITICAL tool stays disabled.
 */
export function isCriticalToolEnabled(toolId: string): boolean {
  const raw = process.env.ENABLE_CRITICAL_TOOLS || "";
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
    .includes(toolId.toLowerCase());
}
