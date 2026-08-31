import { describe, it, expect, beforeAll } from "vitest";

beforeAll(() => {
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
});

import { agentManager } from "../src/server/agents/index";
import { WebAgent } from "../src/server/agents/web/agent";
import { CodeAgent } from "../src/server/agents/code/agent";
import { runMission } from "../src/server/orchestrator/index";

describe("agent registry", () => {
  it("exposes recon, web and code agents with distinct tool allowlists", () => {
    const ids = agentManager.list().map((d) => d.id);
    expect(ids).toEqual(["code_security", "recon", "remediation", "reporting", "testing", "validation", "web_security"]);
  });

  it("routes by capability rather than by hardcoded id", () => {
    expect(agentManager.findByCapability("static-analysis").map((d) => d.id)).toEqual(["code_security"]);
    expect(agentManager.findByCapability("web-scanning").map((d) => d.id)).toEqual(["web_security"]);
  });
});

describe("WebAgent", () => {
  it("returns detections that are explicitly unconfirmed", async () => {
    const res = await new WebAgent().run({ target: "http://192.168.1.50:8080" });
    expect(res.agentId).toBe("web_security");
    expect(res.data.detections.every((d) => d.validated === false)).toBe(true);
    expect(res.data.analysis).toHaveProperty("falsePositiveRisks");
  });

  it("propagates a gateway denial for an out-of-scope target", async () => {
    await expect(new WebAgent().run({ target: "http://8.8.8.8" })).rejects.toThrow();
  });
});

describe("CodeAgent", () => {
  it("refuses a workspace path it cannot contain, rather than degrading", async () => {
    await expect(
      new CodeAgent().run({ workspacePath: "../../etc" }),
    ).rejects.toThrow(/Workspace path rejected/);
  });
});

describe("orchestrator chaining", () => {
  it("skips the web step with a stated reason when recon found no HTTP service", async () => {
    // The simulated sandbox produces no nmap port rows, so nothing is open.
    const plan: any = await runMission({
      userPrompt: "assess the staging host",
      target: "192.168.1.50",
      projectId: "proj_alpha_lab",
    });
    expect(plan.engine.reconReal).toBe(true);
    expect(plan.engine.webReal).toBe(false);
    expect(plan.engine.webSkippedReason).toMatch(/no open HTTP service/);

    const webStep = plan.steps.find((s: any) => s.agent === "web_security");
    expect(webStep.status).toBe("SKIPPED");
    expect(webStep.real).toBe(false);
  });

  it("marks a step COMPLETED only when its agent actually ran", async () => {
    const plan: any = await runMission({ userPrompt: "assess", target: "192.168.1.50" });
    const byAgent = Object.fromEntries(plan.steps.map((s: any) => [s.agent, s]));

    // The simulated sandbox yields no open ports, so nothing was found. With no
    // findings there is nothing to validate and nothing to remediate: those
    // steps must stay PENDING rather than report success over an empty set.
    expect(byAgent.vuln_analysis.status).toBe("PENDING");
    expect(byAgent.remediation.status).toBe("PENDING");

    // These two do real work regardless of findings.
    expect(byAgent.testing.status).toBe("COMPLETED");
    expect(byAgent.testing.real).toBe(true);
    expect(byAgent.reporting.status).toBe("COMPLETED");
    expect(byAgent.reporting.real).toBe(true);

    expect(plan.status).toBe("PARTIAL");
    // Every step claiming COMPLETED must be backed by a real run.
    for (const s of plan.steps) {
      if (s.status === "COMPLETED" && !["orchestrator", "gateway"].includes(s.agent)) {
        expect(s.real).toBe(true);
      }
    }
  });

  it("probes its own security controls on every mission and reports no breach", async () => {
    const plan: any = await runMission({ userPrompt: "assess", target: "192.168.1.50" });
    expect(plan.engine.controlsProbed).toBeGreaterThan(12);
    expect(plan.engine.controlsBreached).toBe(0);
    expect(plan.controls.allControlsHeld).toBe(true);
  });

  it("emits a report that separates confirmed findings from detections", async () => {
    const plan: any = await runMission({ userPrompt: "assess", target: "192.168.1.50", language: "en" });
    expect(plan.reportMarkdown).toContain("## 3. Confirmed findings");
    expect(plan.reportMarkdown).toContain("## 4. Unconfirmed detections");
    // Coverage must state what did NOT run, with a reason.
    const web = plan.coverage.find((c: any) => c.area === "Web application scanning");
    expect(web.performed).toBe(false);
    expect(web.detail).toMatch(/Not performed/);
  });
});
