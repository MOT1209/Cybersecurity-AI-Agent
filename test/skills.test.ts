/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Skill platform tests: real discovery from disk, schema validation,
 * security scanning, and the honest executable/not-executable distinction.
 */

import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { discoverSkills } from "../src/server/skills/loader";
import { scanSkillManifest } from "../src/server/skills/scanner";
import {
  initializeSkillRegistry,
  isSkillRegistered,
  isSkillExecutable,
  getSkill,
  listSkills,
  listSkillLoadFailures,
} from "../src/server/skills/registry";
import { SkillManifestSchema } from "../src/server/skills/manifest";
import { dispatchSkill, SkillNotRegisteredError, SkillNotExecutableError } from "../src/server/skills/dispatcher";
import { GatewayDeniedError } from "../src/server/sandbox/index";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "local";
  process.env.AI_PROVIDER = "local";
  delete process.env.APP_ACCESS_KEY;
  delete process.env.API_PRINCIPALS;
});

import { createApp } from "../server";

async function makeFixtureRoot(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "cyberguard-skills-test-"));
}

async function writeSkill(root: string, id: string, manifest: Record<string, unknown>, opts?: { skipDoc?: boolean; badJson?: boolean }) {
  const dir = path.join(root, id);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(
    path.join(dir, "skill.json"),
    opts?.badJson ? "{ not valid json" : JSON.stringify(manifest, null, 2),
  );
  if (!opts?.skipDoc) {
    await fs.writeFile(path.join(dir, "SKILL.md"), `# ${id}\n`);
  }
  return dir;
}

const baseManifest = (overrides: Record<string, unknown> = {}) => ({
  id: "test-skill",
  name: "Test Skill",
  version: "1.0.0",
  author: "test",
  description: "A test skill.",
  capabilities: ["test"],
  requiredTools: [],
  requiredMcp: [],
  permissions: [],
  riskLevel: "LOW",
  dependencies: [],
  inputSchema: { type: "object" },
  outputSchema: { type: "object" },
  securityPolicy: { maxRiskLevel: "LOW", scopeEnforced: true, alwaysRequireApproval: false },
  ...overrides,
});

describe("real skill packages under src/server/skills/definitions", () => {
  it("discovers and registers nmap-recon and sast-review as executable", async () => {
    const { registered, failed } = await initializeSkillRegistry(undefined, true);
    expect(registered).toBeGreaterThanOrEqual(2);
    expect(failed).toBe(0);
    expect(isSkillRegistered("nmap-recon")).toBe(true);
    expect(isSkillRegistered("sast-review")).toBe(true);
    expect(isSkillExecutable("nmap-recon")).toBe(true);
    expect(isSkillExecutable("sast-review")).toBe(true);
  });

  it("carries a manifest whose requiredTools are real platform adapters", () => {
    const skill = getSkill("nmap-recon")!;
    expect(skill.manifest.requiredTools).toEqual(["nmap"]);
    expect(skill.scan.passed).toBe(true);
  });

  it("lists skills sorted by id", () => {
    const ids = listSkills().map((s) => s.manifest.id);
    expect(ids).toEqual([...ids].sort());
  });
});

describe("manifest schema validation", () => {
  it("accepts a well-formed manifest", () => {
    expect(SkillManifestSchema.safeParse(baseManifest()).success).toBe(true);
  });

  it("rejects a non-kebab-case id", () => {
    expect(SkillManifestSchema.safeParse(baseManifest({ id: "Not Valid" })).success).toBe(false);
  });

  it("rejects a non-semver version", () => {
    expect(SkillManifestSchema.safeParse(baseManifest({ version: "v1" })).success).toBe(false);
  });

  it("rejects an unknown riskLevel", () => {
    expect(SkillManifestSchema.safeParse(baseManifest({ riskLevel: "EXTREME" })).success).toBe(false);
  });
});

describe("discovery from disk (fixture root)", () => {
  it("loads a well-formed skill package", async () => {
    const root = await makeFixtureRoot();
    await writeSkill(root, "test-skill", baseManifest());
    const { loaded, failed } = await discoverSkills(root);
    expect(loaded).toHaveLength(1);
    expect(failed).toHaveLength(0);
    expect(loaded[0].manifest.id).toBe("test-skill");
  });

  it("records a failure for invalid JSON, never silently drops or coerces it", async () => {
    const root = await makeFixtureRoot();
    await writeSkill(root, "broken-json", {}, { badJson: true });
    const { loaded, failed } = await discoverSkills(root);
    expect(loaded).toHaveLength(0);
    expect(failed).toHaveLength(1);
    expect(failed[0].reason).toMatch(/not valid JSON/);
  });

  it("records a failure for a manifest that fails schema validation", async () => {
    const root = await makeFixtureRoot();
    await writeSkill(root, "bad-manifest", baseManifest({ id: "bad-manifest", version: "not-semver" }));
    const { loaded, failed } = await discoverSkills(root);
    expect(loaded).toHaveLength(0);
    expect(failed[0].reason).toMatch(/schema validation/);
  });

  it("requires SKILL.md — an undocumented skill is not loadable", async () => {
    const root = await makeFixtureRoot();
    await writeSkill(root, "test-skill", baseManifest(), { skipDoc: true });
    const { loaded, failed } = await discoverSkills(root);
    expect(loaded).toHaveLength(0);
    expect(failed[0].reason).toMatch(/SKILL\.md/);
  });

  it("rejects a directory name that doesn't match the manifest's own id", async () => {
    const root = await makeFixtureRoot();
    await writeSkill(root, "wrong-dir-name", baseManifest({ id: "actual-id" }));
    const { loaded, failed } = await discoverSkills(root);
    expect(loaded).toHaveLength(0);
    expect(failed[0].reason).toMatch(/does not match manifest id/);
  });

  it("returns an empty (not thrown) result for a nonexistent root", async () => {
    const { loaded, failed } = await discoverSkills(path.join(os.tmpdir(), "does-not-exist-" + Date.now()));
    expect(loaded).toEqual([]);
    expect(failed).toEqual([]);
  });
});

describe("security scan — the honest executable bar", () => {
  it("fails a skill that requires a tool with no real adapter", () => {
    const result = scanSkillManifest(baseManifest({ requiredTools: ["totally-fake-tool"] }) as never, new Set());
    expect(result.passed).toBe(false);
    expect(result.findings.find((f) => f.check === "required-tools-implemented")?.passed).toBe(false);
  });

  it("fails any skill that declares an MCP requirement — no MCP platform exists", () => {
    const result = scanSkillManifest(baseManifest({ requiredMcp: ["some-mcp-server"] }) as never, new Set());
    expect(result.passed).toBe(false);
    const finding = result.findings.find((f) => f.check === "no-unavailable-mcp-dependency");
    expect(finding?.passed).toBe(false);
    expect(finding?.detail).toMatch(/NOT_AVAILABLE/);
  });

  it("fails a skill declaring a permission outside the allowlist", () => {
    const result = scanSkillManifest(baseManifest({ permissions: ["root:everything"] }) as never, new Set());
    expect(result.passed).toBe(false);
    expect(result.findings.find((f) => f.check === "permissions-allowlisted")?.passed).toBe(false);
  });

  it("fails a skill depending on an unregistered sibling skill", () => {
    const result = scanSkillManifest(baseManifest({ dependencies: ["nonexistent-skill"] }) as never, new Set(["some-other-skill"]));
    expect(result.passed).toBe(false);
    expect(result.findings.find((f) => f.check === "dependencies-registered")?.passed).toBe(false);
  });

  it("passes when a dependency IS registered", () => {
    const result = scanSkillManifest(baseManifest({ dependencies: ["sibling"] }) as never, new Set(["sibling"]));
    expect(result.findings.find((f) => f.check === "dependencies-registered")?.passed).toBe(true);
  });

  it("disables a CRITICAL-risk skill by default (mirrors CRITICAL tool policy)", () => {
    const result = scanSkillManifest(
      baseManifest({ riskLevel: "CRITICAL", securityPolicy: { maxRiskLevel: "CRITICAL", scopeEnforced: true, alwaysRequireApproval: true } }) as never,
      new Set(),
    );
    expect(result.passed).toBe(false);
    expect(result.findings.find((f) => f.check === "critical-risk-enabled")?.passed).toBe(false);
  });

  it("fails when securityPolicy.maxRiskLevel is lower than the skill's own riskLevel", () => {
    const result = scanSkillManifest(
      baseManifest({ riskLevel: "HIGH", securityPolicy: { maxRiskLevel: "LOW", scopeEnforced: true, alwaysRequireApproval: false } }) as never,
      new Set(),
    );
    expect(result.passed).toBe(false);
    expect(result.findings.find((f) => f.check === "security-policy-consistent")?.passed).toBe(false);
  });

  it("passes a fully clean, dependency-free, tool-free manifest", () => {
    const result = scanSkillManifest(baseManifest() as never, new Set());
    expect(result.passed).toBe(true);
    expect(result.findings.every((f) => f.passed)).toBe(true);
  });
});

describe("registry against a fixture root end-to-end", () => {
  it("registers a passing skill and records a failing one as not executable, never silently promoted", async () => {
    const root = await makeFixtureRoot();
    await writeSkill(root, "good-skill", baseManifest({ id: "good-skill" }));
    await writeSkill(root, "bad-tool-skill", baseManifest({ id: "bad-tool-skill", requiredTools: ["fake-tool"] }));

    const { registered, failed } = await initializeSkillRegistry(root, true);
    expect(registered).toBe(2);
    expect(failed).toBe(0);
    expect(isSkillExecutable("good-skill")).toBe(true);
    expect(isSkillExecutable("bad-tool-skill")).toBe(false);

    // Restore the real registry so it doesn't leak into other test files.
    await initializeSkillRegistry(undefined, true);
    expect(listSkillLoadFailures()).toEqual([]);
  });
});

describe("skill dispatch — the part that was explicitly missing", () => {
  it("throws for an unregistered skill id, never fabricates a result", async () => {
    await expect(dispatchSkill("does-not-exist", "192.168.1.50", {})).rejects.toBeInstanceOf(
      SkillNotRegisteredError,
    );
  });

  it("throws for a registered-but-not-executable skill, with the failing reasons attached", async () => {
    const root = await makeFixtureRoot();
    await writeSkill(root, "unexecutable-skill", baseManifest({ id: "unexecutable-skill", requiredTools: ["fake-tool"] }));
    await initializeSkillRegistry(root, true);
    try {
      await expect(dispatchSkill("unexecutable-skill", "192.168.1.50", {})).rejects.toBeInstanceOf(
        SkillNotExecutableError,
      );
    } finally {
      await initializeSkillRegistry(undefined, true);
    }
  });

  it("actually runs the underlying tool for a real, executable skill (nmap-recon)", async () => {
    const result = await dispatchSkill("nmap-recon", "192.168.1.50", {}, { projectId: "proj_alpha_lab" });
    expect(result.toolId).toBe("nmap");
    expect(result.status).toBe("SUCCESS");
    expect(result.structuredData).toHaveProperty("openPortCount");
  });

  it("still enforces the security gateway — an out-of-scope target is denied, not silently run", async () => {
    await expect(dispatchSkill("nmap-recon", "8.8.8.8", {}, { projectId: "proj_alpha_lab" })).rejects.toBeInstanceOf(
      GatewayDeniedError,
    );
  });
});

describe("skill routes", () => {
  it("GET /api/skills lists the real registered skills with scan results", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/skills").expect(200);
    const ids = res.body.skills.map((s: { id: string }) => s.id);
    expect(ids).toContain("nmap-recon");
    expect(ids).toContain("sast-review");
    const nmapSkill = res.body.skills.find((s: { id: string }) => s.id === "nmap-recon");
    expect(nmapSkill.executable).toBe(true);
    expect(nmapSkill.scan.passed).toBe(true);
  });

  it("GET /api/skills/:id returns the full manifest for a registered skill", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/skills/sast-review").expect(200);
    expect(res.body.manifest.id).toBe("sast-review");
    expect(res.body.manifest.requiredTools).toEqual(["semgrep"]);
  });

  it("GET /api/skills/:id 404s honestly for an unregistered id, never a fake record", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/skills/does-not-exist").expect(404);
    expect(res.body.error).toBe("SKILL_NOT_REGISTERED");
  });
});
