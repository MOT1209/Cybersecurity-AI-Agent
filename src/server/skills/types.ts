/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Skill contract (§8). A Skill is a declared capability with its own tool
 * requirements, agent allowlist, I/O schemas and security requirements — not a
 * prompt. The registry is populated in a later phase; this file fixes the
 * contract so agents and tools can reference it now.
 */

import type { ZodTypeAny } from "zod";
import type { RiskLevel } from "../tools/types";

export interface SkillSecurityRequirements {
  /** Tool risk level this skill is permitted to reach. */
  maxRiskLevel: RiskLevel;
  /** Skill may only run against targets inside the project scope. */
  scopeEnforced: boolean;
  /** Human approval is always required, regardless of tool risk. */
  alwaysRequireApproval: boolean;
}

export interface SkillDescriptor {
  id: string;
  name: string;
  description: string;
  version: string;
  capabilities: string[];
  /** Tool ids this skill needs; all must be registered AND implemented. */
  requiredTools: string[];
  /** Agent ids permitted to invoke this skill. */
  allowedAgents: string[];
  inputSchema: ZodTypeAny;
  outputSchema: ZodTypeAny;
  securityRequirements: SkillSecurityRequirements;
  /** Post-execution assertions the result must satisfy to be trusted. */
  validationRules: string[];
}
