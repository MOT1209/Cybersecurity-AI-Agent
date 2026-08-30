import { describe, it, expect, beforeAll } from "vitest";

// Force deterministic, offline behavior: simulation executor + local LLM.
beforeAll(() => {
  process.env.SANDBOX_MODE = "local";
  process.env.AI_PROVIDER = "local";
});

import { executeTool, GatewayDeniedError } from "../src/server/sandbox/index";
import { buildNmapRequest, parseNmapOutput, NmapParamsSchema } from "../src/server/tools/nmap";
import { auditLogsStore } from "../src/server/core/index";
import { ReconAgent } from "../src/server/agents/recon/agent";

describe("executeTool (gateway + sandbox)", () => {
  it("runs an in-scope tool in the simulation sandbox and audits with an outputHash", async () => {
    const before = auditLogsStore.length;
    const result = await executeTool({ toolId: "subfinder", target: "192.168.1.50" });
    expect(result.status).toBe("SUCCESS");
    expect(result.sandbox.mode).toBe("local-sim");
    // The gateway writes an ALLOWED entry, then the run writes the hashed entry.
    expect(auditLogsStore.length).toBeGreaterThan(before);
    expect(auditLogsStore[0].action).toBe("RUN_SUBFINDER");
    expect(auditLogsStore[0].outputHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("rejects an out-of-scope target before any execution", async () => {
    await expect(executeTool({ toolId: "nmap", target: "8.8.8.8" })).rejects.toBeInstanceOf(
      GatewayDeniedError,
    );
  });
});

describe("nmap adapter", () => {
  it("builds a safe TCP connect argument vector with the target last", () => {
    const req = buildNmapRequest("192.168.1.50", { ports: "22,80", serviceDetection: true });
    expect(req.args).toEqual(["-sT", "-T4", "-p", "22,80", "-sV", "192.168.1.50"]);
    expect(req.args[req.args.length - 1]).toBe("192.168.1.50");
  });

  it("rejects invalid port specs via the zod schema", () => {
    expect(() => NmapParamsSchema.parse({ ports: "80; rm -rf" })).toThrow();
  });

  it("parses PORT/STATE/SERVICE rows from raw output", () => {
    const raw = "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n443/tcp closed https";
    const ports = parseNmapOutput(raw);
    expect(ports).toHaveLength(3);
    expect(ports[0]).toEqual({ port: 22, protocol: "tcp", state: "open", service: "ssh" });
  });
});

describe("ReconAgent", () => {
  it("produces a recon result with a local-fallback analysis when no model is set", async () => {
    const agent = new ReconAgent();
    const res = await agent.run({ target: "192.168.1.50" });
    expect(res.agentId).toBe("recon");
    expect(res.data.sandboxMode).toBe("local-sim");
    expect(res.provider).toBe("local");
    expect(res.fallback).toBe(true);
    expect(res.toolCalls[0].tool).toBe("nmap");
    expect(res.data.analysis).toHaveProperty("nextSteps");
  });
});
