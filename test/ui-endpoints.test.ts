import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import path from "path";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
  delete process.env.APP_ACCESS_KEY;
  delete process.env.API_PRINCIPALS;
});

import { createApp } from "../server";
import { migrationsDir, listMigrationFiles } from "../src/server/database/migrate";
import { resetPrincipals } from "../src/server/security/principal";

/**
 * These lock the exact response shapes the new frontend pages read. A backend
 * change that silently drops one of these fields would put the UI back to
 * displaying nothing (or worse, a stale assumption) with no test failing.
 */
describe("contracts the UI pages depend on", () => {
  it("GET /api/tools/health gives every field the Tool Registry page renders", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/tools/health").expect(200);
    expect(Array.isArray(res.body.tools)).toBe(true);
    for (const t of res.body.tools) {
      expect(t).toHaveProperty("toolId");
      expect(t).toHaveProperty("name");
      expect(t).toHaveProperty("state");
      expect(t).toHaveProperty("reason");
      expect(t).toHaveProperty("riskLevel");
      expect(t).toHaveProperty("implemented");
      expect(t).toHaveProperty("sandboxRequired");
      // null means "not probed", which the page renders differently from false.
      expect(["boolean", "object"]).toContain(typeof t.imagePresent);
      expect(t.adapterVersion === null || typeof t.adapterVersion === "string").toBe(true);
    }
  });

  it("GET /api/findings gives the counts and validation fields the Findings page renders", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/findings").expect(200);
    for (const key of ["total", "confirmed", "detected", "unconfirmed"]) {
      expect(typeof res.body.counts[key]).toBe("number");
    }
    expect(Array.isArray(res.body.findings)).toBe(true);
  });

  it("GET /api/findings accepts the status filter the page sends", async () => {
    const app = await createApp();
    for (const status of ["CONFIRMED", "DETECTED", "UNCONFIRMED", "FALSE_POSITIVE"]) {
      const res = await request(app).get(`/api/findings?status=${status}`).expect(200);
      expect(res.body.findings.every((f: { validation: { status: string } }) => f.validation.status === status)).toBe(true);
    }
  });

  it("GET /api/approvals never leaks a token into the listing", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/approvals").expect(200);
    expect(Array.isArray(res.body.approvals)).toBe(true);
    expect(JSON.stringify(res.body)).not.toContain('"token"');
  });

  it("GET /api/agents reports only dispatchable agents, so the mesh badges are honest", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/agents").expect(200);
    const ids = res.body.agents.map((a: { id: string }) => a.id).sort();
    // The UI catalog lists twelve; only these are actually executable.
    expect(ids).toEqual(["code_security", "recon", "remediation", "reporting", "testing", "validation", "web_security"]);
    for (const a of res.body.agents) {
      expect(Array.isArray(a.allowedTools)).toBe(true);
      expect(Array.isArray(a.capabilities)).toBe(true);
      expect(a).toHaveProperty("riskLevel");
    }
  });

  it("the recovery stats no longer expose the removed self-healing metrics", async () => {
    const app = await createApp();
    const res = await request(app).get("/api/error-recovery/events").expect(200);
    expect(res.body.stats).not.toHaveProperty("successRatePercentage");
    expect(res.body.stats).not.toHaveProperty("totalRecovered");
    expect(res.body.stats).not.toHaveProperty("fallbacksExecuted");
    for (const key of ["diagnosesRecorded", "escalated", "recoveryProposed", "activeCircuitBreakers"]) {
      expect(typeof res.body.stats[key]).toBe("number");
    }
  });

  it("a diagnosis returns the fields the step panel renders, and claims no retry", async () => {
    const app = await createApp();
    const res = await request(app)
      .post("/api/error-recovery/diagnose-and-retry")
      .send({ toolName: "nmap", target: "192.168.1.50", rawError: "timed out" })
      .expect(200);
    const ev = res.body.event ?? res.body;
    for (const key of ["rootCauseAr", "rootCauseEn", "proposedFixAr", "proposedFixEn", "strategy", "status"]) {
      expect(ev[key]).toBeTruthy();
    }
    expect(ev.recoveryExecuted).toBe(false);
    expect(["RECOVERY_PROPOSED", "ESCALATED"]).toContain(ev.status);
  });

  it("approving requires the approver role, which the page surfaces as an error", async () => {
    process.env.API_PRINCIPALS = "bot:operator:bot-secret";
    resetPrincipals();
    const app = await createApp();
    const blocked = await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", "bot-secret")
      .send({ toolId: "zap", target: "192.168.1.50" })
      .expect(428);
    const res = await request(app)
      .post(`/api/approvals/${blocked.body.approvalId}/decision`)
      .set("x-api-key", "bot-secret")
      .send({ decision: "APPROVED" })
      .expect(403);
    expect(res.body.message).toBeTruthy();
    delete process.env.API_PRINCIPALS;
    resetPrincipals();
  });
});

describe("migration files are reachable from the working directory", () => {
  it("resolves without import.meta so the CJS production bundle can find them", async () => {
    // The bundle does not carry the .sql files next to itself; resolution must
    // come from the working directory, not the module's own location.
    expect(migrationsDir()).toBe(
      path.join(process.cwd(), "src", "server", "database", "migrations"),
    );
    expect(await listMigrationFiles()).toContain("001_init.sql");
  });

  it("honors MIGRATIONS_DIR for a relocated deployment", () => {
    process.env.MIGRATIONS_DIR = "./some/other/place";
    expect(migrationsDir()).toBe(path.resolve("./some/other/place"));
    delete process.env.MIGRATIONS_DIR;
  });
});
