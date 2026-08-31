import { describe, it, expect, beforeAll } from "vitest";
import { z } from "zod";

beforeAll(() => {
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
});

import { AgentManager, agentManager } from "../src/server/agents/manager";
import "../src/server/agents/index"; // triggers registration
import { AgentNotRegisteredError, AgentRunError } from "../src/server/core/errors";
import type { AgentDescriptor, RunnableAgent } from "../src/server/agents/types";

function descriptor(over: Partial<AgentDescriptor> = {}): AgentDescriptor {
  return {
    id: "stub",
    name: "Stub",
    description: "test agent",
    capabilities: ["testing"],
    skills: [],
    allowedTools: [],
    permissions: [],
    riskLevel: "LOW",
    timeoutMs: 1000,
    inputSchema: z.unknown(),
    outputSchema: z.unknown(),
    memoryPolicy: { maxTasks: 1, persistRawOutput: false },
    ...over,
  };
}

function stub(id: string, run: RunnableAgent["run"], over: Partial<AgentDescriptor> = {}): RunnableAgent {
  return { id, describe: () => descriptor({ id, ...over }), run };
}

describe("AgentManager", () => {
  it("registers the recon agent at import time and exposes it via discovery", () => {
    expect(agentManager.has("recon")).toBe(true);
    expect(agentManager.findByCapability("service-discovery").map((d) => d.id)).toContain("recon");
  });

  it("refuses to register an agent whose allowedTools are not in the registry", () => {
    const m = new AgentManager();
    expect(() =>
      m.register(stub("bad", async () => ({}) as never, { allowedTools: ["totally-made-up"] })),
    ).toThrow(/unregistered tools/);
  });

  it("throws AgentNotRegisteredError for an unknown agent id", async () => {
    const m = new AgentManager();
    await expect(m.dispatch("ghost", {})).rejects.toBeInstanceOf(AgentNotRegisteredError);
  });

  it("enforces the declared timeout and records the run as TIMEOUT", async () => {
    const m = new AgentManager();
    m.register(stub("slow", () => new Promise(() => {}), { timeoutMs: 40 }));
    await expect(m.dispatch("slow", {})).rejects.toBeInstanceOf(AgentRunError);
    expect(m.listRuns()[0].state).toBe("TIMEOUT");
  });

  it("captures agent errors in the run record and re-throws them unchanged", async () => {
    const m = new AgentManager();
    const boom = new Error("adapter exploded");
    m.register(stub("boom", async () => { throw boom; }));
    await expect(m.dispatch("boom", {})).rejects.toBe(boom);
    const run = m.listRuns()[0];
    expect(run.state).toBe("FAILED");
    expect(run.error).toBe("adapter exploded");
    expect(run.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("signals cancellation to the agent through the run context", async () => {
    const m = new AgentManager();
    let sawAbort = false;
    m.register(
      stub("cancellable", (_input, ctx) =>
        new Promise((resolve) => {
          ctx!.signal!.addEventListener("abort", () => {
            sawAbort = true;
            resolve({} as never);
          });
        }),
      ),
    );
    const p = m.dispatch("cancellable", {});
    const runId = m.listRuns()[0].runId;
    expect(m.cancel(runId)).toBe(true);
    await p;
    expect(sawAbort).toBe(true);
  });
});
