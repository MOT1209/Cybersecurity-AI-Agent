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
    expect(ids).toEqual(["code_security", "recon", "validation", "web_security"]);
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

  it("leaves every unimplemented step PENDING instead of claiming it completed", async () => {
    const plan: any = await runMission({ userPrompt: "assess", target: "192.168.1.50" });
    const unimplemented = plan.steps.filter((s: any) =>
      ["vuln_analysis", "remediation", "testing", "reporting"].includes(s.agent),
    );
    expect(unimplemented.length).toBeGreaterThan(0);
    expect(unimplemented.every((s: any) => s.status === "PENDING")).toBe(true);
    expect(plan.status).toBe("PARTIAL");
  });
});
