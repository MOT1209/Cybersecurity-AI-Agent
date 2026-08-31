import { describe, it, expect, beforeEach } from "vitest";

import { RemediationAgent, baselineRemediation } from "../src/server/agents/remediation/agent";
import { ReportingAgent, buildReport } from "../src/server/agents/reporting/agent";
import { TestingAgent, runSecurityProbes } from "../src/server/agents/testing/agent";
import { agentManager } from "../src/server/agents/index";
import {
  fromNmapPorts,
  fromNucleiDetections,
  recordFindings,
  listFindings,
  applyValidation,
  resetFindings,
} from "../src/server/findings/engine";
import type { Finding } from "../src/server/findings/types";

const ctx = {
  projectId: "proj_alpha_lab",
  target: "192.168.1.50",
  agentId: "recon",
  toolId: "nmap",
  traceId: "trc_pipeline",
  outputHash: "sha256:" + "b".repeat(64),
};

function seedConfirmed(): Finding {
  const [f] = recordFindings(
    fromNmapPorts([{ port: 22, protocol: "tcp", state: "open", service: "ssh" }], ctx),
  );
  applyValidation(f.id, {
    status: "CONFIRMED",
    confidence: 95,
    validatedByAgent: "validation",
    falsePositiveIndicators: [],
    missingEvidence: [],
  });
  return listFindings().find((x) => x.id === f.id)!;
}

function seedUnconfirmed(): Finding {
  const [f] = recordFindings(
    fromNucleiDetections(
      [
        {
          templateId: "cve-x",
          name: "Remote code execution",
          severity: "critical",
          matchedAt: "http://192.168.1.50:8080/",
          type: "http",
          cwe: ["CWE-502"],
          validated: false,
        },
      ],
      { ...ctx, toolId: "nuclei", agentId: "web_security" },
    ),
  );
  return listFindings().find((x) => x.id === f.id)!;
}

describe("RemediationAgent", () => {
  beforeEach(() => resetFindings());

  it("holds no tools, so it has no way to change a system", () => {
    expect(new RemediationAgent().describe().allowedTools).toEqual([]);
  });

  it("marks guidance for an unconfirmed finding as conditional", () => {
    const r = baselineRemediation(seedUnconfirmed());
    expect(r.summary).toMatch(/^CONDITIONAL/);
    expect(r.hardeningSteps[0]).toMatch(/Validate the finding first/);
  });

  it("does not add the conditional prefix to a confirmed finding", () => {
    const r = baselineRemediation(seedConfirmed());
    expect(r.summary).not.toMatch(/^CONDITIONAL/);
  });

  it("selects guidance by CWE, falling back to the tool, then generic", () => {
    const f = seedUnconfirmed(); // CWE-502 via nuclei
    expect(baselineRemediation(f).summary).toMatch(/deserializ/i);

    const noCwe = { ...seedConfirmed(), cwe: [], toolUsed: "trivy" } as Finding;
    expect(baselineRemediation(noCwe).summary).toMatch(/dependency/i);

    const unknown = { ...seedConfirmed(), cwe: [], toolUsed: "mystery" } as Finding;
    expect(baselineRemediation(unknown).summary).toMatch(/intended configuration/i);
  });

  it("attaches guidance without changing the finding's verification status", async () => {
    const f = seedUnconfirmed();
    await new RemediationAgent().run({ projectId: "proj_alpha_lab" });
    const after = listFindings().find((x) => x.id === f.id)!;
    expect(after.remediation).toBeTruthy();
    // Advice must never promote a detection.
    expect(after.validation.status).toBe("DETECTED");
    expect(after.validation.confidence).toBe(0);
  });
});

describe("ReportingAgent", () => {
  beforeEach(() => resetFindings());

  it("counts only confirmed findings in the executive summary", () => {
    const md = buildReport({
      target: "192.168.1.50",
      projectId: "proj_alpha_lab",
      findings: [seedConfirmed(), seedUnconfirmed(), seedUnconfirmed()],
      coverage: [],
      isAr: false,
    });
    expect(md).toMatch(/\*\*1\*\* finding\(s\) were confirmed/);
    expect(md).toMatch(/further \*\*2\*\* were detected but are NOT confirmed/);
  });

  it("renders confirmed and unconfirmed findings in separate sections", () => {
    const confirmed = seedConfirmed();
    const unconfirmed = seedUnconfirmed();
    const md = buildReport({
      target: "t",
      projectId: "p",
      findings: [confirmed, unconfirmed],
      coverage: [],
      isAr: false,
    });
    const confirmedSection = md.indexOf("## 3. Confirmed findings");
    const unconfirmedSection = md.indexOf("## 4. Unconfirmed detections");
    expect(confirmedSection).toBeGreaterThan(-1);
    expect(unconfirmedSection).toBeGreaterThan(confirmedSection);

    // Each finding must appear on the correct side of the boundary.
    expect(md.indexOf(confirmed.title)).toBeLessThan(unconfirmedSection);
    expect(md.indexOf(unconfirmed.title)).toBeGreaterThan(unconfirmedSection);
  });

  it("states what was NOT assessed rather than silently omitting it", () => {
    const md = buildReport({
      target: "t",
      projectId: "p",
      findings: [],
      coverage: [
        { area: "Web application scanning", performed: false, detail: "Not performed: no HTTP service found" },
      ],
      isAr: false,
    });
    expect(md).toContain("Coverage and what was NOT assessed");
    expect(md).toContain("Not performed: no HTTP service found");
    expect(md).toMatch(/absence of a finding in an area that was not assessed is not evidence/);
  });

  it("labels every finding with its verification status and severity source", () => {
    const md = buildReport({
      target: "t",
      projectId: "p",
      findings: [seedUnconfirmed()],
      coverage: [],
      isAr: false,
    });
    expect(md).toContain("Severity (tool's claim)");
    expect(md).toContain("**DETECTED**");
  });

  it("notes when evidence carries no output hash", () => {
    const f = seedUnconfirmed();
    f.evidence = [{ source: "nuclei", observation: "matched", collectedAt: new Date().toISOString() }];
    const md = buildReport({ target: "t", projectId: "p", findings: [f], coverage: [], isAr: false });
    expect(md).toContain("no output hash");
  });

  it("produces a report with zero findings without inventing any", async () => {
    const res = await new ReportingAgent().run({ projectId: "proj_alpha_lab", language: "en" });
    expect(res.data.confirmedCount).toBe(0);
    expect(res.data.reportMarkdown).toContain("_No findings were confirmed._");
  });
});

describe("TestingAgent", () => {
  it("holds no tools, so the self-test cannot grant itself reach", () => {
    expect(new TestingAgent().describe().allowedTools).toEqual([]);
  });

  it("consults no model — a control verdict is never a model's opinion", async () => {
    const res = await new TestingAgent().run({});
    expect(res.provider).toBe("deterministic");
    expect(res.fallback).toBe(false);
    expect(res.toolCalls).toHaveLength(0);
  });

  it("reports every probed control as held", async () => {
    const probes = await runSecurityProbes("proj_alpha_lab");
    const breached = probes.filter((p) => p.outcome === "BREACHED");
    expect(breached.map((p) => `${p.id}: ${p.detail}`)).toEqual([]);
    expect(probes.length).toBeGreaterThan(12);
  });

  it("covers scope, tool permission, approval, sandbox, injection and audit", async () => {
    const categories = new Set((await runSecurityProbes()).map((p) => p.category));
    expect([...categories].sort()).toEqual([
      "approval-enforcement",
      "audit-integrity",
      "prompt-injection",
      "sandbox-boundary",
      "scope-enforcement",
      "tool-permission",
    ]);
  });

  it("leaves no usable approval token behind after probing", async () => {
    const { listApprovals } = await import("../src/server/security/approvals");
    await runSecurityProbes();
    const probeApprovals = listApprovals().filter((a) => a.requestedBy === "testing-agent-probe");
    // Every probe approval is either consumed or never granted; none is left APPROVED.
    expect(probeApprovals.every((a) => a.status !== "APPROVED")).toBe(true);
  });
});

describe("pipeline agents are registered", () => {
  it("exposes all seven executable agents", () => {
    expect(agentManager.list().map((d) => d.id)).toEqual([
      "code_security",
      "recon",
      "remediation",
      "reporting",
      "testing",
      "validation",
      "web_security",
    ]);
  });

  it("gives every non-scanning agent an empty tool allowlist", () => {
    for (const id of ["validation", "remediation", "reporting", "testing"]) {
      expect(agentManager.get(id).describe().allowedTools).toEqual([]);
    }
  });
});
