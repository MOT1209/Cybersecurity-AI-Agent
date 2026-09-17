/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Catalog service (P2). Validates the fifty-agent manifest at load and merges
 * it with live runtime truth on every call:
 *
 * - an entry is IMPLEMENTED only when a matching agent is registered in the
 *   Agent Manager AND every required tool has a real adapter in the registry;
 * - a registered agent missing tool adapters is PARTIAL, never "implemented";
 * - everything else is CATALOG_ONLY with the reason said plainly.
 *
 * The validator is pure (inputs passed in) so tests can drive every branch
 * without a runtime; the two concrete inputs live at the bottom of this file.
 */

import { agentManager } from "../manager";
import { hasAdapter, listTools } from "../../tools/registry";
import { AGENT_MANIFEST } from "./catalog";
import type {
  AgentManifestEntry,
  CatalogEntry,
  CatalogOverview,
} from "./types";

export { AGENT_MANIFEST };

export const CATALOG_SIZE = 50;

const DOMAINS = new Set([
  "recon", "osint", "web", "validation", "code", "network",
  "cloud", "container", "forensics", "threat-intel",
  "remediation", "reporting", "testing",
]);

const INPUT_KINDS = new Set([
  "target", "code", "artifact", "evidence", "config", "findings", "conversation",
]);

const RISK_LEVELS = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

export interface CatalogValidationContext {
  toolIds: string[];
  registeredAgentIds: string[];
}

/**
 * Validate the manifest. Returns a list of violations — empty means the
 * manifest is sound. Checked at module load; any finding throws, because a
 * published catalog that cannot describe itself honestly must not boot.
 */
export function validateCatalog(
  manifest: unknown,
  ctx: CatalogValidationContext,
): string[] {
  const errors: string[] = [];
  if (!Array.isArray(manifest)) return ["catalog manifest must be an array"];
  const entries = manifest as AgentManifestEntry[];
  if (entries.length !== CATALOG_SIZE) {
    errors.push(`catalog must hold exactly ${CATALOG_SIZE} entries, found ${entries.length}`);
  }
  const seenIds = new Set<string>();
  const ordinals: number[] = [];
  for (const [i, e] of entries.entries()) {
    const where = `entry[${i}]`;
    if (!e || typeof e.id !== "string" || !e.id) errors.push(`${where}: id must be a non-empty string`);
    else if (seenIds.has(e.id)) errors.push(`${where}: duplicate id "${e.id}"`);
    else seenIds.add(e.id);
    if (typeof e.ordinal !== "number" || !Number.isInteger(e.ordinal)) {
      errors.push(`${where} (${e?.id ?? "?"}): ordinal must be an integer`);
    } else ordinals.push(e.ordinal);
    if (!DOMAINS.has(e.domain)) errors.push(`${where} (${e?.id ?? "?"}): unknown domain "${e?.domain}"`);
    if (!INPUT_KINDS.has(e.inputKind)) errors.push(`${where} (${e?.id ?? "?"}): unknown inputKind "${e?.inputKind}"`);
    if (!RISK_LEVELS.has(e.riskLevel)) errors.push(`${where} (${e?.id ?? "?"}): unknown riskLevel "${e?.riskLevel}"`);
    for (const f of ["nameEn", "nameAr", "descriptionEn", "descriptionAr"] as const) {
      if (typeof e[f] !== "string" || !e[f].trim()) {
        errors.push(`${where} (${e?.id ?? "?"}): ${f} must be a non-empty string`);
      }
    }
    for (const f of ["capabilities", "skills", "permissions"] as const) {
      if (!Array.isArray(e[f]) || e[f].some((v) => typeof v !== "string" || !v)) {
        errors.push(`${where} (${e?.id ?? "?"}): ${f} must be an array of non-empty strings`);
      }
    }
    if (!Array.isArray(e.requiredTools)) {
      errors.push(`${where} (${e?.id ?? "?"}): requiredTools must be an array`);
    } else {
      for (const t of e.requiredTools) {
        if (typeof t !== "string" || !ctx.toolIds.includes(t)) {
          errors.push(`${where} (${e?.id ?? "?"}): required tool "${t}" is not in the tool registry`);
        }
      }
    }
  }
  const sorted = [...ordinals].sort((a, b) => a - b);
  for (let n = 1; n <= CATALOG_SIZE; n++) {
    if (sorted[n - 1] !== n) {
      errors.push(`ordinals must be contiguous 1..${CATALOG_SIZE}; position ${n} is missing or duplicated`);
      break;
    }
  }
  for (const id of ctx.registeredAgentIds) {
    if (!seenIds.has(id)) {
      errors.push(`runtime agent "${id}" is registered but has no catalog entry — the catalog must describe everything that runs`);
    }
  }
  return errors;
}

/**
 * Merge one manifest entry with runtime truth. For registered agents the
 * descriptor is authoritative: name, description, capabilities, skills, tools,
 * permissions and risk come from the live agent, never from a hand-entered
 * copy, so the two cannot drift.
 */
export function toCatalogEntry(entry: AgentManifestEntry): CatalogEntry {
  const registered = agentManager.has(entry.id);
  const d = registered ? agentManager.get(entry.id).describe() : undefined;

  const base: AgentManifestEntry = d
    ? {
        ...entry,
        nameEn: d.name,
        descriptionEn: d.description,
        capabilities: d.capabilities,
        skills: d.skills,
        requiredTools: d.allowedTools,
        permissions: d.permissions,
        riskLevel: d.riskLevel,
      }
    : { ...entry, requiredTools: [...entry.requiredTools] };

  const requiredToolsWithState = base.requiredTools.map((id) => ({
    id,
    implemented: hasAdapter(id),
  }));
  const missing = requiredToolsWithState.filter((t) => !t.implemented).map((t) => t.id);

  if (!registered) {
    return {
      ...base,
      status: "CATALOG_ONLY",
      registered: false,
      requiredToolsWithState,
      reason: "No runtime agent is registered for this entry; the planned tools are listed but there is nothing to dispatch to.",
    };
  }
  if (missing.length) {
    return {
      ...base,
      status: "PARTIAL",
      registered: true,
      requiredToolsWithState,
      reason: `Registered, but these required tools have no adapter yet: ${missing.join(", ")}.`,
    };
  }
  return { ...base, status: "IMPLEMENTED", registered: true, requiredToolsWithState };
}

/** The whole catalog with live statuses, ordered by ordinal. */
export function catalogEntries(): CatalogEntry[] {
  return AGENT_MANIFEST.map(toCatalogEntry).sort((a, b) => a.ordinal - b.ordinal);
}

export function catalogOverview(entries: CatalogEntry[] = catalogEntries()): CatalogOverview {
  const byDomain: CatalogOverview["byDomain"] = {};
  const missing = new Set<string>();
  let implemented = 0;
  let partial = 0;
  for (const e of entries) {
    const slot = (byDomain[e.domain] ??= { total: 0, implemented: 0 });
    slot.total += 1;
    if (e.status === "IMPLEMENTED") {
      implemented += 1;
      slot.implemented += 1;
    } else if (e.status === "PARTIAL") {
      partial += 1;
    }
    for (const t of e.requiredToolsWithState) {
      if (!t.implemented) missing.add(t.id);
    }
  }
  return {
    count: entries.length,
    implemented,
    partial,
    catalogOnly: entries.length - implemented - partial,
    byDomain,
    missingAdapters: [...missing].sort(),
  };
}

export function catalogValidationContext(): CatalogValidationContext {
  return {
    toolIds: listTools().map((t) => t.descriptor.id),
    registeredAgentIds: agentManager.list().map((d) => d.id),
  };
}

// The manifest is the contract: the agents barrel asserts it after
// registration (see src/server/agents/index.ts), so import order cannot
// run this check before the runtime agents exist.

export type { AgentManifestEntry, CatalogEntry, CatalogOverview };
