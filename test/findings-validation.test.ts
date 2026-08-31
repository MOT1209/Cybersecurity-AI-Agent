import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import request from "supertest";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
  delete process.env.APP_ACCESS_KEY;
});

import { createApp } from "../server";
import {
  fromNmapPorts,
  fromNucleiDetections,
  fromSemgrepFindings,
  fromTrivyFindings,
  recordFindings,
  listFindings,
  resetFindings,
} from "../src/server/findings/engine";
import { ValidationAgent, assessEvidence } from "../src/server/agents/validation/agent";
import type { Finding } from "../src/server/findings/types";

const ctx = {
  projectId: "proj_alpha_lab",
  target: "192.168.1.50",
  agentId: "recon",
  toolId: "nmap",
  traceId: "trc_findings",
  outputHash: "sha256:" + "a".repeat(64),
};

describe("findings engine", () => {
  beforeEach(() => resetFindings());

  it("enters every normalized detection at DETECTED with zero confidence", () => {
    const all: Finding[] = [
      ...fromNmapPorts([{ port: 22, protocol: "tcp", state: "open", service: "ssh" }], ctx),
      ...fromNucleiDetections(
        [{ templateId: "t", name: "n", severity: "critical", matchedAt: "u", type: "http", validated: false }],
        { ...ctx, toolId: "nuclei", agentId: "web_security" },
      ),
      ...fromSemgrepFindings(
        [{ ruleId: "r", message: "m", severity: "high", path: "a.js", startLine: 1, endLine: 2, cwe: ["CWE-89"], owasp: [], validated: false }],
        { ...ctx, toolId: "semgrep", agentId: "code_security" },
      ),
      ...fromTrivyFindings(
        [{ id: "CVE-1", kind: "vulnerability", title: "t", severity: "critical", target: "pkg", validated: false }],
        { ...ctx, toolId: "trivy", agentId: "code_security" },
      ),
    ];
    expect(all).toHaveLength(4);
    for (const f of all) {
      expect(f.validation.status).toBe("DETECTED");
      expect(f.validation.confidence).toBe(0);
    }
  });

  it("ignores closed ports rather than reporting them as exposure", () => {
    const f = fromNmapPorts(
      [
        { port: 22, protocol: "tcp", state: "open", service: "ssh" },
        { port: 443, protocol: "tcp", state: "closed", service: "https" },
      ],
      ctx,
    );
    expect(f).toHaveLength(1);
  });

  it("carries the output hash onto the evidence so a finding is traceable", () => {
    const f = fromNmapPorts([{ port: 22, protocol: "tcp", state: "open", service: "ssh" }], ctx);
    expect(f[0].evidence[0].outputHash).toBe(ctx.outputHash);
  });

  it("filters by status, trace and minimum severity", () => {
    recordFindings(fromNmapPorts([{ port: 23, protocol: "tcp", state: "open", service: "telnet" }], ctx));
    recordFindings(fromNmapPorts([{ port: 22, protocol: "tcp", state: "open", service: "ssh" }], ctx));
    expect(listFindings({ traceId: "trc_findings" })).toHaveLength(2);
    expect(listFindings({ minSeverity: "MEDIUM" })).toHaveLength(1);
    expect(listFindings({ status: "CONFIRMED" })).toHaveLength(0);
  });
});

describe("evidence assessment (deterministic core)", () => {
  const make = (over: Partial<Finding>): Finding =>
    ({
      ...fromNmapPorts([{ port: 22, protocol: "tcp", state: "open", service: "ssh" }], ctx)[0],
      ...over,
    }) as Finding;

  it("confirms a direct, traceable observation", () => {
    const a = assessEvidence(make({}), "proj_alpha_lab");
    expect(a.status).toBe("CONFIRMED");
    expect(a.confidence).toBeGreaterThanOrEqual(70);
  });

  it("refuses to confirm an inferential tool result", () => {
    const a = assessEvidence(make({ toolUsed: "nuclei" }), "proj_alpha_lab");
    expect(a.status).toBe("UNCONFIRMED");
    expect(a.falsePositiveIndicators.join(" ")).toMatch(/inferential/);
    expect(a.missingEvidence.length).toBeGreaterThan(0);
  });

  it("caps confidence when the evidence has no traceable output hash", () => {
    const f = make({});
    f.evidence = [{ source: "nmap", observation: "22/tcp open ssh", collectedAt: new Date().toISOString() }];
    const a = assessEvidence(f, "proj_alpha_lab");
    expect(a.confidence).toBeLessThanOrEqual(40);
    expect(a.status).toBe("UNCONFIRMED");
  });

  it("never confirms a finding about an out-of-scope asset", () => {
    const a = assessEvidence(make({ target: "8.8.8.8" }), "proj_alpha_lab");
    expect(a.status).toBe("UNCONFIRMED");
    expect(a.confidence).toBe(0);
  });

  it("refuses a finding with no recorded observation", () => {
    const a = assessEvidence(make({ evidence: [] }), "proj_alpha_lab");
    expect(a.status).toBe("UNCONFIRMED");
    expect(a.falsePositiveIndicators).toContain("Finding carries no evidence.");
  });
});

describe("ValidationAgent", () => {
  beforeEach(() => resetFindings());

  it("applies verdicts and never promotes an inferential detection", async () => {
    recordFindings(
      fromNucleiDetections(
        [{ templateId: "cve-x", name: "RCE", severity: "critical", matchedAt: "http://192.168.1.50:8080/", type: "http", validated: false }],
        { ...ctx, toolId: "nuclei", agentId: "web_security" },
      ),
    );
    const res = await new ValidationAgent().run({ projectId: "proj_alpha_lab", traceId: "trc_findings" });
    expect(res.data.verdicts).toHaveLength(1);
    expect(res.data.confirmed).toBe(0);
    expect(listFindings()[0].validation.status).toBe("UNCONFIRMED");
    expect(listFindings()[0].validation.validatedByAgent).toBe("validation");
  });

  it("records a rationale and the evidence still missing", async () => {
    recordFindings(
      fromSemgrepFindings(
        [{ ruleId: "sqli", message: "m", severity: "high", path: "a.js", startLine: 1, endLine: 1, cwe: ["CWE-89"], owasp: [], validated: false }],
        { ...ctx, toolId: "semgrep", agentId: "code_security" },
      ),
    );
    await new ValidationAgent().run({ projectId: "proj_alpha_lab" });
    const v = listFindings()[0].validation;
    expect(v.rationale).toBeTruthy();
    expect(v.missingEvidence.length).toBeGreaterThan(0);
  });

  it("performs no tool calls — validation is evidence review, not exploitation", async () => {
    recordFindings(fromNmapPorts([{ port: 22, protocol: "tcp", state: "open", service: "ssh" }], ctx));
    const res = await new ValidationAgent().run({ projectId: "proj_alpha_lab" });
    expect(res.toolCalls).toHaveLength(0);
  });
});

describe("findings API", () => {
  beforeEach(() => resetFindings());

  it("reports counts by verification status", async () => {
    recordFindings(fromNmapPorts([{ port: 22, protocol: "tcp", state: "open", service: "ssh" }], ctx));
    const app = await createApp();
    const res = await request(app).get("/api/findings").expect(200);
    expect(res.body.counts.total).toBe(1);
    expect(res.body.counts.detected).toBe(1);
    expect(res.body.counts.confirmed).toBe(0);
  });

  it("404s an unknown finding id", async () => {
    const app = await createApp();
    await request(app).get("/api/findings/find_nope").expect(404);
  });
});
