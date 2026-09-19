/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * On-disk skill manifest contract (skill.json). Distinct from
 * `SkillDescriptor` in types.ts — that type carries live ZodTypeAny I/O
 * schemas for a skill defined in TypeScript; a manifest loaded from JSON on
 * disk cannot serialize a Zod schema, so its I/O contract is a plain
 * JSON-Schema-shaped object instead. The loader in loader.ts is what turns a
 * validated manifest into a registry record.
 */

import { z } from "zod";

export const RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

/** A minimal JSON-Schema-shaped description — just enough to document the
 *  contract; not a validating schema engine. */
const jsonSchemaShape = z.object({
  type: z.string(),
  properties: z.record(z.string(), z.unknown()).optional(),
  required: z.array(z.string()).optional(),
}).passthrough();

export const SkillSecurityPolicySchema = z.object({
  /** Tool risk level this skill is permitted to reach. */
  maxRiskLevel: z.enum(RISK_LEVELS),
  /** Skill may only run against targets inside the project scope. */
  scopeEnforced: z.boolean().default(true),
  /** Human approval is always required, regardless of tool risk. */
  alwaysRequireApproval: z.boolean().default(false),
});

export const SkillManifestSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/, "id must be lowercase kebab-case"),
  name: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/, "version must be semver, e.g. 1.0.0"),
  author: z.string().min(1),
  description: z.string().min(1),
  capabilities: z.array(z.string()).min(1),
  /** Tool ids this skill needs. All must be REGISTERED AND IMPLEMENTED for
   *  the skill to be executable — see registry.ts's live status computation. */
  requiredTools: z.array(z.string()).default([]),
  /** MCP server ids this skill needs. The platform has no MCP layer yet
   *  (see docs/architecture/current-state.md §4), so any skill naming one
   *  here can never be marked executable — that is the honest, intended
   *  behavior, not a bug to work around. */
  requiredMcp: z.array(z.string()).default([]),
  /** Coarse capability tags, checked against a fixed allowlist at load time. */
  permissions: z.array(z.string()).default([]),
  riskLevel: z.enum(RISK_LEVELS),
  /** Other skill ids this skill depends on. Checked for existence at load
   *  time; a skill depending on an unregistered skill is not executable. */
  dependencies: z.array(z.string()).default([]),
  inputSchema: jsonSchemaShape,
  outputSchema: jsonSchemaShape,
  securityPolicy: SkillSecurityPolicySchema,
});

export type SkillManifest = z.infer<typeof SkillManifestSchema>;
