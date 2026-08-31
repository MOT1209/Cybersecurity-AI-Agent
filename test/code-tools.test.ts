import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "fs/promises";
import path from "path";
import os from "os";

let root: string;

beforeAll(async () => {
  process.env.SANDBOX_MODE = "simulate";
  root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "cg-ws-")));
  await fs.mkdir(path.join(root, "repo"));
  await fs.writeFile(path.join(root, "repo", "app.js"), "console.log(1)");
  process.env.SANDBOX_WORKSPACE_ROOT = root;
});

afterAll(async () => {
  await fs.rm(root, { recursive: true, force: true });
  delete process.env.SANDBOX_WORKSPACE_ROOT;
});

import { resolveWorkspacePath, CONTAINER_WORKSPACE } from "../src/server/security/workspace";
import { buildSemgrepRequest, parseSemgrepOutput, SemgrepParamsSchema } from "../src/server/tools/semgrep";
import { buildTrivyRequest, parseTrivyOutput, TrivyParamsSchema } from "../src/server/tools/trivy";
import { getToolDescriptor } from "../src/server/tools/registry";

describe("workspace containment", () => {
  it("resolves a path inside the root to a container-side path", async () => {
    const r = await resolveWorkspacePath("repo");
    expect(r.ok).toBe(true);
    expect(r.containerPath).toBe(`${CONTAINER_WORKSPACE}/repo`);
    expect(r.hostPath).toBe(path.join(root, "repo"));
  });

  it("rejects traversal out of the workspace root", async () => {
    for (const bad of ["../..", "repo/../../../etc", "/etc", "../"]) {
      const r = await resolveWorkspacePath(bad);
      expect(r.ok).toBe(false);
    }
  });

  it("rejects a symlink that points outside the root", async () => {
    const link = path.join(root, "escape");
    try {
      await fs.symlink(os.tmpdir(), link, "dir");
    } catch {
      return; // symlink creation may need privileges on Windows
    }
    const r = await resolveWorkspacePath("escape");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/outside the workspace root/);
  });

  it("rejects a path that does not exist and a null byte", async () => {
    expect((await resolveWorkspacePath("nope")).ok).toBe(false);
    expect((await resolveWorkspacePath("repo\0x")).ok).toBe(false);
  });

  it("refuses to mount the root itself", async () => {
    expect((await resolveWorkspacePath(".")).ok).toBe(false);
  });
});

describe("semgrep adapter", () => {
  it("only accepts curated rulesets — never a URL or local rule file", () => {
    expect(() => SemgrepParamsSchema.parse({ ruleset: "https://evil.example/rules.yaml" })).toThrow();
    expect(() => SemgrepParamsSchema.parse({ ruleset: "/tmp/rules.yaml" })).toThrow();
    expect(() => SemgrepParamsSchema.parse({ ruleset: "p/owasp-top-ten" })).not.toThrow();
  });

  it("disables telemetry and version checks and excludes minified bundles", () => {
    const args = buildSemgrepRequest("/workspace/repo", {}).args;
    expect(args).toContain("--metrics=off");
    expect(args).toContain("--disable-version-check");
    expect(args).toContain("node_modules");
    expect(args[args.length - 1]).toBe("/workspace/repo");
  });

  it("parses results with CWE/OWASP metadata and marks them unvalidated", () => {
    const raw = JSON.stringify({
      results: [
        {
          check_id: "javascript.express.sqli",
          path: "/workspace/repo/app.js",
          start: { line: 12 },
          end: { line: 14 },
          extra: {
            message: "SQL injection",
            severity: "ERROR",
            metadata: { cwe: ["CWE-89"], owasp: ["A03:2021"] },
          },
        },
        { path: "no check_id" },
      ],
    });
    const f = parseSemgrepOutput(raw);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].cwe).toEqual(["CWE-89"]);
    expect(f[0].validated).toBe(false);
  });

  it("returns [] rather than throwing on unparseable output", () => {
    expect(parseSemgrepOutput("semgrep: fatal error")).toEqual([]);
  });
});

describe("trivy adapter", () => {
  it("does not expose remote image scanning through a mode flag", () => {
    expect(() => TrivyParamsSchema.parse({ scanType: "image" })).toThrow();
    expect(() => TrivyParamsSchema.parse({ scanType: "fs" })).not.toThrow();
  });

  it("runs fully offline", () => {
    const args = buildTrivyRequest("/workspace/repo", {}).args;
    expect(args).toContain("--offline-scan");
    expect(args).toContain("--skip-db-update");
  });

  it("parses vulnerabilities, secrets and misconfigurations", () => {
    const raw = JSON.stringify({
      Results: [
        {
          Target: "package-lock.json",
          Vulnerabilities: [
            { VulnerabilityID: "CVE-2024-1", Title: "bad", Severity: "HIGH", PkgName: "lodash", FixedVersion: "4.17.21" },
          ],
          Secrets: [{ RuleID: "aws-access-key", Title: "AWS key", Severity: "CRITICAL", Match: "AKIA_SECRET_VALUE" }],
          Misconfigurations: [{ ID: "DS002", Title: "root user", Severity: "MEDIUM" }],
        },
      ],
    });
    const f = parseTrivyOutput(raw);
    expect(f.map((x) => x.kind)).toEqual(["vulnerability", "secret", "misconfiguration"]);
    expect(f.every((x) => x.validated === false)).toBe(true);
    // The matched secret value must never reach structured output.
    expect(JSON.stringify(f)).not.toContain("AKIA_SECRET_VALUE");
  });
});

describe("code tool descriptors", () => {
  it("are filesystem-scoped, network-free and workspace-read-only", () => {
    for (const id of ["semgrep", "trivy"]) {
      const d = getToolDescriptor(id)!;
      expect(d.targetKind).toBe("filesystem");
      expect(d.needsNetwork).toBe(false);
      expect(d.filesystemAccess).toBe("workspace-ro");
    }
  });
});
