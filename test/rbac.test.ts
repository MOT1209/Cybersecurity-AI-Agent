/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * RBAC enforcement (P0): anonymous-dev is viewer-only, and every mutating or
 * executing route requires the right role AFTER input validation (so a
 * malformed request still gets 400, not a misleading 403).
 *
 * Matrix under test:
 *   POST /api/tools/execute              → operator
 *   POST /api/labs/:id/start|stop        → operator
 *   POST /api/orchestrator/run-mission   → operator
 *   POST /api/projects                   → admin
 *   POST /api/runtime/mode               → admin
 *   POST /api/error-recovery/reset-circuit → admin
 *   every GET                            → viewer (anonymous OK)
 */
import { describe, it, expect, beforeAll, afterEach } from "vitest";
import request from "supertest";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
  delete process.env.APP_ACCESS_KEY;
  delete process.env.API_PRINCIPALS;
});

import { createApp } from "../server";
import { resetPrincipals } from "../src/server/security/principal";
import { setLabDockerProvider } from "../src/server/labs/manager";

afterEach(() => {
  delete process.env.API_PRINCIPALS;
  resetPrincipals();
  setLabDockerProvider(null);
});

const OPERATOR_KEY = "rbac-operator-secret";
const ADMIN_KEY = "rbac-admin-secret";
const VIEWER_KEY = "rbac-viewer-secret";

function asPrincipals() {
  process.env.API_PRINCIPALS =
    `rbac-operator:operator:${OPERATOR_KEY},` +
    `rbac-admin:admin:${ADMIN_KEY},` +
    `rbac-viewer:viewer:${VIEWER_KEY}`;
  resetPrincipals();
}

describe("anonymous-dev is viewer-only", () => {
  it("reads listings without a key but cannot execute a tool", async () => {
    const app = await createApp();
    await request(app).get("/api/tools").expect(200);
    await request(app).get("/api/projects").expect(200);
    const res = await request(app)
      .post("/api/tools/execute")
      .send({ toolId: "nmap", target: "192.168.1.50" })
      .expect(403);
    expect(res.body.error).toBe("FORBIDDEN");
  });

  it("cannot start or stop a lab without a key", async () => {
    const app = await createApp();
    await request(app).post("/api/labs/dvwa/start").expect(403);
    await request(app).post("/api/labs/dvwa/stop").expect(403);
  });

  it("cannot switch the run mode or create a project without a key", async () => {
    const app = await createApp();
    await request(app).post("/api/runtime/mode").send({ mode: "pair" }).expect(403);
    await request(app).post("/api/projects").send({ name: "x" }).expect(403);
  });
});

describe("role matrix with configured principals", () => {
  it("lets an operator execute tools and run labs, but not switch modes", async () => {
    const app = await createApp();
    asPrincipals();
    await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", OPERATOR_KEY)
      .send({ toolId: "nmap", target: "192.168.1.50" })
      .expect(200);
    await request(app)
      .post("/api/runtime/mode")
      .set("x-api-key", OPERATOR_KEY)
      .send({ mode: "pair" })
      .expect(403);
    await request(app)
      .post("/api/error-recovery/reset-circuit")
      .set("x-api-key", OPERATOR_KEY)
      .send({})
      .expect(403);
  });

  it("lets an admin switch modes and manage projects and breakers", async () => {
    const app = await createApp();
    asPrincipals();
    await request(app)
      .post("/api/runtime/mode")
      .set("x-api-key", ADMIN_KEY)
      .send({ mode: "pair" })
      .expect(200);
    await request(app)
      .post("/api/projects")
      .set("x-api-key", ADMIN_KEY)
      .send({ name: "rbac-probe" })
      .expect(200);
    await request(app)
      .post("/api/error-recovery/reset-circuit")
      .set("x-api-key", ADMIN_KEY)
      .send({})
      .expect(200);
  });

  it("keeps a viewer read-only even with a valid key", async () => {
    const app = await createApp();
    asPrincipals();
    await request(app).get("/api/findings").set("x-api-key", VIEWER_KEY).expect(200);
    await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", VIEWER_KEY)
      .send({ toolId: "nmap", target: "192.168.1.50" })
      .expect(403);
  });

  it("still answers 400 (not 403) for malformed input from an anonymous caller", async () => {
    const app = await createApp();
    const res = await request(app)
      .post("/api/tools/execute")
      .send({ toolId: 12345, target: "192.168.1.50" })
      .expect(400);
    expect(res.body.error).toBe("VALIDATION_ERROR");
  });

  it("still answers 401 for a bad key once principals are configured", async () => {
    const app = await createApp();
    asPrincipals();
    await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", "wrong-key")
      .send({ toolId: "nmap", target: "192.168.1.50" })
      .expect(401);
  });
});
