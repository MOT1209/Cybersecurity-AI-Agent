import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import request from "supertest";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
  delete process.env.APP_ACCESS_KEY;
  delete process.env.ENABLE_CRITICAL_TOOLS;
  // Two distinct identities: a scanner that may run tools but may not approve,
  // and a human operator holding the approver role.
  process.env.API_PRINCIPALS =
    "scanner-bot:operator:scanner-secret,human-operator:operator|approver:human-secret";
  resetPrincipals();
});

import { createApp } from "../server";
import { executeTool, ApprovalRequiredError } from "../src/server/sandbox/index";
import {
  createApprovalRequest,
  decideApproval,
  consumeApproval,
  listApprovals,
  resetApprovals,
} from "../src/server/security/approvals";
import { validateSecurityGateway } from "../src/server/core/gateway";
import { resetPrincipals } from "../src/server/security/principal";

const base = {
  task: "Active web scan",
  target: "192.168.1.50",
  toolId: "zap",
  reason: "Authorized engagement test",
  scope: "proj_alpha_lab",
  riskLevel: "HIGH" as const,
  expectedImpact: "Sends active probes to the staging web app",
  projectId: "proj_alpha_lab",
  requestedBy: "api-client",
};

describe("approval system", () => {
  beforeEach(() => resetApprovals());

  it("never exposes the token in a listing", () => {
    const r = createApprovalRequest(base);
    decideApproval(r.id, "APPROVED", "human-operator");
    expect(listApprovals()[0]).not.toHaveProperty("token");
  });

  it("refuses self-approval: the approver must differ from the requester", () => {
    const r = createApprovalRequest(base);
    const bad = decideApproval(r.id, "APPROVED", "api-client");
    expect(bad.ok).toBe(false);
    expect(bad.error).toMatch(/Self-approval is not permitted/);
    expect(listApprovals()[0].status).toBe("PENDING");
  });

  it("binds a token to one tool+target and burns it after a single use", () => {
    const r = createApprovalRequest(base);
    const token = decideApproval(r.id, "APPROVED", "human-operator").approval!.token!;

    expect(consumeApproval(token, "nmap", "192.168.1.50").ok).toBe(false);
    expect(consumeApproval(token, "zap", "192.168.1.51").ok).toBe(false);
    expect(consumeApproval(token, "zap", "192.168.1.50").ok).toBe(true);
    // Burned.
    expect(consumeApproval(token, "zap", "192.168.1.50").ok).toBe(false);
  });

  it("rejects a decision on an already-decided request", () => {
    const r = createApprovalRequest(base);
    decideApproval(r.id, "REJECTED", "human-operator");
    expect(decideApproval(r.id, "APPROVED", "human-operator").ok).toBe(false);
  });

  it("does not mint a token for a rejection", () => {
    const r = createApprovalRequest(base);
    const out = decideApproval(r.id, "REJECTED", "human-operator");
    expect(out.ok).toBe(true);
    expect(out.approval!.token).toBeUndefined();
  });
});

describe("gateway policy pipeline", () => {
  it("derives risk from the tool registry, not a hardcoded name list", () => {
    expect(validateSecurityGateway("192.168.1.50", "nmap").riskLevel).toBe("MEDIUM");
    expect(validateSecurityGateway("192.168.1.50", "zap").riskLevel).toBe("HIGH");
  });

  it("treats an unregistered tool as CRITICAL and denies it", () => {
    const d = validateSecurityGateway("192.168.1.50", "made-up-tool");
    expect(d.riskLevel).toBe("CRITICAL");
    expect(d.isAllowed).toBe(false);
  });

  it("returns an ordered record of the checks it performed", () => {
    const d = validateSecurityGateway("192.168.1.50", "nmap");
    expect(d.checks.map((c) => c.name)).toEqual([
      "target-denylist",
      "target-allowlist",
      "project-tool-permission",
      "risk-policy",
      "approval-requirement",
    ]);
    expect(d.checks.every((c) => c.passed)).toBe(true);
  });
});

/**
 * Mint an approved, unused token through the domain API rather than over HTTP.
 *
 * The approval store is the same module-level singleton the routes read, so this
 * is exactly the state a human's decision produces — it just lets a test assert
 * one HTTP hop instead of four. The HTTP decision route itself is covered by
 * "lets a separate human decide it" below, so nothing is bypassed silently.
 */
function approvedToken(): string {
  const opened = createApprovalRequest(base);
  const decided = decideApproval(opened.id, "APPROVED", "human-operator");
  expect(decided.ok).toBe(true);
  return decided.approval!.token!;
}

/**
 * These assertions used to share ONE test — create, decide, execute, replay, all
 * over HTTP — which measured 3194 ms against vitest's 5000 ms default on an idle
 * machine. Under a full-suite run it crossed the budget and failed as a bare
 * "Test timed out in 5000ms", naming none of the four claims it was carrying.
 *
 * A longer testTimeout would have bought silence; what the test needed was to
 * stop carrying four claims. Each block below now drives only the hop it
 * asserts, and each stays within two HTTP requests.
 */
describe("approval enforcement end to end", () => {
  beforeEach(() => resetApprovals());

  it("a caller cannot authorize its own high-risk execution", async () => {
    // There is deliberately no boolean flag to set. Without a human-issued
    // token the run is refused.
    await expect(executeTool({ toolId: "zap", target: "192.168.1.50" })).rejects.toBeInstanceOf(
      ApprovalRequiredError,
    );
  });

  it("428 opens a real approval request, and leaks no token to the caller", async () => {
    const app = await createApp();
    const blocked = await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", "scanner-secret")
      .send({ toolId: "zap", target: "192.168.1.50" })
      .expect(428);
    expect(blocked.body.error).toBe("APPROVAL_REQUIRED");
    expect(blocked.body.humanApprovalRequired).toBe(true);
    expect(blocked.body.approvalId).toMatch(/^apr_/);
    expect(blocked.body.approval.requestedBy).toBe("scanner-bot");
    // The whole point of the 428: the requester gets an id to act on later, never
    // the credential that would let it act now.
    expect(blocked.body.approval.token).toBeUndefined();

    // "A human can act on it" means discoverable by a human, so check the read
    // path too rather than trusting the id in the reply.
    const listed = await request(app)
      .get("/api/approvals")
      .set("x-api-key", "human-secret")
      .expect(200);
    const opened = listed.body.approvals.find(
      (a: { id: string }) => a.id === blocked.body.approvalId,
    );
    expect(opened).toBeDefined();
    expect(opened.status).toBe("PENDING");
    expect(opened.token).toBeUndefined();
  });

  it("lets a separate human decide it, and mints the token only then", async () => {
    const app = await createApp();
    const blocked = await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", "scanner-secret")
      .send({ toolId: "zap", target: "192.168.1.50" })
      .expect(428);

    const decided = await request(app)
      .post(`/api/approvals/${blocked.body.approvalId}/decision`)
      .set("x-api-key", "human-secret")
      .send({ decision: "APPROVED" })
      .expect(200);
    expect(decided.body.approval.status).toBe("APPROVED");
    // The decider is the authenticated principal, not a name from the body.
    expect(decided.body.approval.decidedBy).toBe("human-operator");
    expect(decided.body.approval.token).toBeUndefined();
    expect(decided.body.approvalToken).toMatch(/^[0-9a-f]{64}$/);
  });

  it("executes once the approved token is presented, and says it was a simulation", async () => {
    const app = await createApp();
    const run = await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", "scanner-secret")
      .send({ toolId: "zap", target: "192.168.1.50", approvalToken: approvedToken() })
      .expect(200);
    expect(run.body.status).toBe("SUCCESS");
    // SUCCESS here means the simulated run completed. `zap` has no adapter and
    // SANDBOX_MODE is simulate, so the response must carry that labelling
    // through the HTTP layer — otherwise a 200 would read as a real ZAP scan.
    expect(run.body.sandbox.mode).toBe("local-sim");
    expect(run.body.rawOutput).toContain("SIMULATED — NOT A REAL RESULT");
  });

  it("refuses an already-spent token, with 428 and a fresh request to act on", async () => {
    const app = await createApp();
    const token = approvedToken();
    // Spend it through the same consume path the route uses, then present it.
    // (That the first presentation succeeds is the test above; this is about the
    // second one, so burning it directly avoids re-running the first.)
    expect(consumeApproval(token, "zap", "192.168.1.50").ok).toBe(true);

    const replay = await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", "scanner-secret")
      .send({ toolId: "zap", target: "192.168.1.50", approvalToken: token })
      .expect(428);
    expect(replay.body.error).toBe("APPROVAL_REQUIRED");
    expect(replay.body.approvalId).toMatch(/^apr_/);
    // A refused replay must not echo the spent credential back.
    expect(replay.body.approval.token).toBeUndefined();
  });

  it("refuses a self-approval with 409 even when the caller holds approver", async () => {
    const app = await createApp();
    const blocked = await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", "human-secret")
      .send({ toolId: "zap", target: "192.168.1.50" })
      .expect(428);
    // Same identity requested it, so it cannot decide it.
    await request(app)
      .post(`/api/approvals/${blocked.body.approvalId}/decision`)
      .set("x-api-key", "human-secret")
      .send({ decision: "APPROVED" })
      .expect(409);
  });

  it("refuses a decision from a principal without the approver role", async () => {
    const app = await createApp();
    const blocked = await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", "scanner-secret")
      .send({ toolId: "zap", target: "192.168.1.50" })
      .expect(428);
    const res = await request(app)
      .post(`/api/approvals/${blocked.body.approvalId}/decision`)
      .set("x-api-key", "scanner-secret")
      .send({ decision: "APPROVED" })
      .expect(403);
    expect(res.body.error).toBe("FORBIDDEN");
  });

  it("cannot name someone else as the decider through the request body", async () => {
    const app = await createApp();
    const blocked = await request(app)
      .post("/api/tools/execute")
      .set("x-api-key", "human-secret")
      .send({ toolId: "zap", target: "192.168.1.50" })
      .expect(428);
    // decidedBy in the body is ignored; the authenticated identity is used, so
    // this is still a self-approval and is refused.
    await request(app)
      .post(`/api/approvals/${blocked.body.approvalId}/decision`)
      .set("x-api-key", "human-secret")
      .send({ decision: "APPROVED", decidedBy: "someone-else" })
      .expect(409);
  });
});
