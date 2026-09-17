/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Agent catalog contract (P2). One manifest is the single source of truth for
 * the fifty agents the platform ships. Every entry is honest about what it
 * needs: the tools it references must exist in the tool registry, and the
 * runtime service never reports an entry as implemented unless the matching
 * agent is registered in the Agent Manager AND every required tool has a real
 * adapter.
 */

import type { RiskLevel } from "../../tools/types";

export type AgentDomain =
  | "recon"
  | "osint"
  | "web"
  | "validation"
  | "code"
  | "network"
  | "cloud"
  | "container"
  | "forensics"
  | "threat-intel"
  | "remediation"
  | "reporting"
  | "testing";

/** What the agent operates on, which shapes which tools can serve it. */
export type AgentInputKind =
  | "target"
  | "code"
  | "artifact"
  | "evidence"
  | "config"
  | "findings"
  | "conversation";

export interface AgentManifestEntry {
  /** Stable, URL-safe id. Runtime agents keep their registered ids. */
  id: string;
  /** Serial position within the fifty-agent catalog, 1..50. */
  ordinal: number;
  domain: AgentDomain;
  nameEn: string;
  nameAr: string;
  descriptionEn: string;
  descriptionAr: string;
  capabilities: string[];
  /** Skill ids this agent may select. */
  skills: string[];
  /**
   * Tool ids the agent requires. Validated at load: every id must exist in
   * the tool registry (implemented or declared) — a manifest that references a
   * tool the platform does not know is a build-time error, not a runtime surprise.
   */
  requiredTools: string[];
  permissions: string[];
  riskLevel: RiskLevel;
  inputKind: AgentInputKind;
}

/** An entry merged with live runtime truth. */
export interface CatalogEntry extends AgentManifestEntry {
  status: "IMPLEMENTED" | "PARTIAL" | "CATALOG_ONLY";
  /** True when a matching agent is registered in the Agent Manager. */
  registered: boolean;
  requiredToolsWithState: { id: string; implemented: boolean }[];
  /** Why not IMPLEMENTED, when it is not — said plainly. */
  reason?: string;
}

export interface CatalogOverview {
  count: number;
  implemented: number;
  partial: number;
  catalogOnly: number;
  byDomain: Record<string, { total: number; implemented: number }>;
  /** Tool ids a catalog entry requires but only has declared, not adapted. */
  missingAdapters: string[];
}