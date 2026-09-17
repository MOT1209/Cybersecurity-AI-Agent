/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Catalog tests (P2). The fifty-agent manifest is a contract: exactly fifty
 * entries, contiguous ordinals, tool references that exist in the registry,
 * and — the load-bearing property — a status that reports runtime truth.
 * An entry the platform cannot execute must never read IMPLEMENTED.
 */

import { describe, expect, it } from "vitest";
import "../src/server/agents/index"; // registers the seven runtime agents
import { agentManager } from "../src/server/agents/manager";
import { AGENT_MANIFEST } from "../src/server/agents/catalog/catalog";
import {
  CATALOG_SIZE,
  catalogEntries,
  catalogOverview,
  catalogValidationContext,
  toCatalogEntry,
  validateCatalog,
} from "../src/server/agents/catalog/index";
import type { AgentManifestEntry } from "../src/server/agents/catalog/types";

const ctx = catalogValidationContext();

describe("agent catalog manifest", () => {
  it("validates cleanly against the live tool registry and runtime agents", () => {
    expect(validateCatalog(AGENT_MANIFEST, ctx)).toEqual([]);
  });

  it("holds exactly fifty entries with contiguous ordinals 1..50", () => {
    expect(AGENT_MANIFEST).toHaveLength(CATALOG_SIZE);
    const ordinals = AGENT_MANIFEST.map((e) => e.ordinal).sort((a, b) => a - b);
    for (let n = 1; n <= CATALOG_SIZE; n++) expect(ordinals[n - 1]).toBe(n);
    const ids = AGENT_MANIFEST.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every runtime agent has a catalog entry", () => {
    const manifestIds = new Set(AGENT_MANIFEST.map((e) => e.id));
    for (const d of agentManager.list()) {
      expect(manifestIds.has(d.id)).toBe(true);
    }
  });

  it("rejects a manifest with a duplicate id", () => {
    const dup = [...AGENT_MANIFEST.slice(0, 49), { ...AGENT_MANIFEST[0], ordinal: 50 }];
    const errors = validateCatalog(dup, ctx);
    expect(errors.some((e) => e.includes('duplicate id "recon"'))).toBe(true);
  });

  it("rejects a manifest with a broken ordinal sequence", () => {
    const broken = AGENT_MANIFEST.map((e) => ({ ...e }));
    broken[49] = { ...broken[49], ordinal: 51 };
    const errors = validateCatalog(broken, ctx);
    expect(errors.some((e) => e.includes("contiguous"))).toBe(true);
  });

  it("rejects an entry that references a tool the registry does not know", () => {
    const bad = AGENT_MANIFEST.map((e) => ({ ...e }));
    bad[0] = { ...bad[0], requiredTools: [...bad[0].requiredTools, "ghost_tool"] };
    const errors = validateCatalog(bad, ctx);
    expect(errors.some((e) => e.includes('"ghost_tool"'))).toBe(true);
  });

  it("rejects a registered agent that the catalog does not describe", () => {
    const errors = validateCatalog(AGENT_MANIFEST, {
      ...ctx,
      registeredAgentIds: [...ctx.registeredAgentIds, "ghost_agent"],
    });
    expect(errors.some((e) => e.includes('"ghost_agent"'))).toBe(true);
  });
});

describe("agent catalog statuses", () => {
  const entries = catalogEntries();

  it("marks the seven runtime agents IMPLEMENTED and the rest CATALOG_ONLY", () => {
    const byStatus = new Map(entries.map((e) => [e.id, e.status]));
    for (const d of agentManager.list()) {
      expect(byStatus.get(d.id)).toBe("IMPLEMENTED");
    }
    const implemented = entries.filter((e) => e.status === "IMPLEMENTED");
    expect(implemented).toHaveLength(agentManager.list().length);
    const overview = catalogOverview(entries);
    expect(overview).toMatchObject({
      count: 50,
      implemented: agentManager.list().length,
      partial: 0,
      catalogOnly: 50 - agentManager.list().length,
    });
  });

  it("overlays the live descriptor, so manifest claims cannot drift", () => {
    const recon = entries.find((e) => e.id === "recon")!;
    const d = agentManager.get("recon").describe();
    expect(recon.nameEn).toBe(d.name);
    expect(recon.descriptionEn).toBe(d.description);
    expect(recon.capabilities).toEqual(d.capabilities);
    expect(recon.skills).toEqual(d.skills);
    expect(recon.requiredTools).toEqual(d.allowedTools);
    expect(recon.riskLevel).toBe(d.riskLevel);
  });

  it("a catalog-only entry states plainly why it is not executable", () => {
    const df = entries.find((e) => e.id === "digital_forensics")!;
    expect(df.status).toBe("CATALOG_ONLY");
    expect(df.registered).toBe(false);
    expect(df.reason).toMatch(/no runtime agent/i);
    expect(df.requiredToolsWithState).toEqual([{ id: "volatility", implemented: false }]);
  });

  it("a registered agent missing a tool adapter is PARTIAL, never IMPLEMENTED", () => {
    // zap is declared in the registry but has no adapter — a registered agent
    // that depends on it must surface that gap instead of claiming readiness.
    agentManager.register({
      id: "tmp_partial_probe",
      describe: () => ({
        id: "tmp_partial_probe",
        name: "Temporary partial probe",
        description: "Test-only agent requiring an unadapted tool.",
        capabilities: ["dast"],
        skills: [],
        allowedTools: ["zap"],
        permissions: [],
        riskLevel: "HIGH" as const,
        timeoutMs: 1000,
        inputSchema: undefined as never,
        outputSchema: undefined as never,
        memoryPolicy: { maxTasks: 1, persistRawOutput: false },
      }),
      run: async () => {
        throw new Error("never dispatched in this test");
      },
    });
    const probe: AgentManifestEntry = {
      id: "tmp_partial_probe",
      ordinal: 99,
      domain: "web",
      nameEn: "Temporary partial probe",
      nameAr: "مسبار مؤقت",
      descriptionEn: "Test-only.",
      descriptionAr: "للاختبار فقط.",
      capabilities: ["dast"],
      skills: [],
      requiredTools: ["zap"],
      permissions: [],
      riskLevel: "HIGH",
      inputKind: "target",
    };
    const entry = toCatalogEntry(probe);
    expect(entry.status).toBe("PARTIAL");
    expect(entry.reason).toMatch(/zap/);
  });

  it("the overview names the tool adapters the catalog still needs", () => {
    const overview = catalogOverview(entries);
    expect(overview.missingAdapters).toEqual(["prowler", "volatility", "zap"]);
  });
});
