import { describe, it, expect, beforeAll } from "vitest";

beforeAll(() => {
  process.env.SANDBOX_MODE = "local";
  process.env.AI_PROVIDER = "local";
});

import { runMission, GatewayDeniedError } from "../src/server/orchestrator/index";

describe("runMission", () => {
  it("runs real recon and returns a compatible plan with a template fallback synthesis", async () => {
    const plan: any = await runMission({
      userPrompt: "Assess the staging web app for injection issues",
      target: "192.168.1.50",
      projectId: "proj_alpha_lab",
      language: "ar",
    });

    // Shape the SPA depends on.
    expect(plan).toHaveProperty("id");
    expect(plan).toHaveProperty("traceId");
    expect(Array.isArray(plan.steps)).toBe(true);
    expect(Array.isArray(plan.generatedFindings)).toBe(true);
    expect(plan.participatingAgents).toContain("recon");

    // The recon step is real (nmap in the sandbox).
    const reconStep = plan.steps.find((s: any) => s.agent === "recon");
    expect(reconStep.real).toBe(true);
    expect(reconStep.toolName).toBe("nmap (sandbox)");

    // Engine metadata: recon real, LLM degraded to template (no model configured).
    expect(plan.engine.reconReal).toBe(true);
    expect(plan.engine.sandboxMode).toBe("local-sim");
    expect(plan.engine.llmProvider).toBe("local");
    expect(plan.engine.llmFallback).toBe(true);
  });

  it("propagates a gateway denial for an out-of-scope target", async () => {
    await expect(
      runMission({ userPrompt: "scan", target: "8.8.8.8" }),
    ).rejects.toBeInstanceOf(GatewayDeniedError);
  });
});
