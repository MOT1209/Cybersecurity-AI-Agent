import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import request from "supertest";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
  delete process.env.APP_ACCESS_KEY;
});

import { createApp } from "../server";
import { emitEvent, listEvents, onEvent, resetEvents } from "../src/server/core/events";
import { executeTool } from "../src/server/sandbox/index";

describe("event bus", () => {
  beforeEach(() => resetEvents());

  it("stamps every event with an id, a trace id and a timestamp", () => {
    const e = emitEvent("TASK_CREATED", { target: "192.168.1.50" });
    expect(e.eventId).toMatch(/^evt_/);
    expect(e.traceId).toMatch(/^trc_/);
    expect(Date.parse(e.timestamp)).not.toBeNaN();
  });

  it("filters the buffer by trace id", () => {
    emitEvent("TASK_STARTED", { traceId: "trc_a" });
    emitEvent("TASK_STARTED", { traceId: "trc_b" });
    emitEvent("TASK_COMPLETED", { traceId: "trc_a" });
    expect(listEvents({ traceId: "trc_a" })).toHaveLength(2);
  });

  it("never lets a throwing subscriber break the emitter", () => {
    onEvent(() => {
      throw new Error("bad subscriber");
    });
    expect(() => emitEvent("TASK_FAILED", {})).not.toThrow();
  });

  it("emits the full request→approve→start→complete sequence for a tool run", async () => {
    await executeTool({ toolId: "nmap", target: "192.168.1.50", traceId: "trc_run", image: "x" });
    const types = listEvents({ traceId: "trc_run" }).map((e) => e.type).reverse();
    expect(types).toEqual(["TOOL_REQUESTED", "TOOL_APPROVED", "TOOL_STARTED", "TOOL_COMPLETED"]);
  });

  it("emits TOOL_DENIED and no TOOL_STARTED for an out-of-scope target", async () => {
    await executeTool({ toolId: "nmap", target: "8.8.8.8", traceId: "trc_deny" }).catch(() => {});
    const types = listEvents({ traceId: "trc_deny" }).map((e) => e.type);
    expect(types).toContain("TOOL_DENIED");
    expect(types).not.toContain("TOOL_STARTED");
  });
});

describe("introspection APIs", () => {
  it("GET /api/tools distinguishes implemented adapters from declared-only tools", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/tools").expect(200);
    const byId = Object.fromEntries(res.body.tools.map((t: any) => [t.descriptor.id, t]));
    expect(byId.nmap.implemented).toBe(true);
    expect(byId.zap.implemented).toBe(false);
    // Zod schemas are not serializable and must not be emitted as empty objects.
    expect(byId.nmap.descriptor).not.toHaveProperty("inputSchema");
  });

  it("GET /api/tools/health reports a real state with a reason for every tool", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/tools/health").expect(200);
    for (const t of res.body.tools) {
      expect(t.reason).toBeTruthy();
      expect(["READY", "SIMULATED_ONLY", "NOT_INSTALLED", "NOT_IMPLEMENTED", "SANDBOX_UNAVAILABLE"]).toContain(t.state);
    }
    const zap = res.body.tools.find((t: any) => t.toolId === "zap");
    expect(zap.state).toBe("NOT_IMPLEMENTED");
    expect(zap.adapterVersion).toBeNull();
  });

  it("GET /api/agents lists only registered, executable agents", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/agents").expect(200);
    const byId = Object.fromEntries(res.body.agents.map((a: any) => [a.id, a]));
    expect(Object.keys(byId).sort()).toEqual(["code_security", "recon", "web_security"]);
    expect(byId.recon.allowedTools).toEqual(["nmap"]);
    expect(byId.web_security.allowedTools).toEqual(["nuclei"]);
    expect(byId.code_security.allowedTools).toEqual(["semgrep", "trivy"]);
    // Only agents with a real implementation are listed; the other nine
    // catalog entries in the UI are not registered.
    expect(res.body.agents).toHaveLength(3);
  });

  it("GET /api/tools/execute rejects an unregistered tool with 400", async () => {
    const app = await createApp();
    const res = await request(app)
      .post("/api/tools/execute")
      .send({ toolId: "definitely-not-a-tool", target: "192.168.1.50" })
      .expect(400);
    expect(res.body.error).toBe("TOOL_NOT_REGISTERED");
  });
});
