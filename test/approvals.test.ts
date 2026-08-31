import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import request from "supertest";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
  delete process.env.APP_ACCESS_KEY;
  delete process.env.ENABLE_CRITICAL_TOOLS;
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

describe("approval enforcement end to end", () => {
  beforeEach(() => resetApprovals());

  it("a caller cannot authorize its own high-risk execution", async () => {
    // There is deliberately no boolean flag to set. Without a human-issued
    // token the run is refused.
    await expect(executeTool({ toolId: "zap", target: "192.168.1.50" })).rejects.toBeInstanceOf(
      ApprovalRequiredError,
    );
  });

  it("428 opens a real approval request the operator can act on", async () => {
    const app = await createApp();
    const blocked = await request(app)
      .post("/api/tools/execute")
      .send({ toolId: "zap", target: "192.168.1.50" })
      .expect(428);
    expect(blocked.body.approvalId).toMatch(/^apr_/);
    expect(blocked.body.approval.token).toBeUndefined();

    const decided = await request(app)
      .post(`/api/approvals/${blocked.body.approvalId}/decision`)
      .send({ decision: "APPROVED", decidedBy: "human-operator" })
      .expect(200);
    expect(decided.body.approvalToken).toMatch(/^[0-9a-f]{64}$/);

    const run = await request(app)
      .post("/api/tools/execute")
      .send({ toolId: "zap", target: "192.168.1.50", approvalToken: decided.body.approvalToken })
      .expect(200);
    expect(run.body.status).toBe("SUCCESS");

    // The token is single-use: replaying it fails.
    await request(app)
      .post("/api/tools/execute")
      .send({ toolId: "zap", target: "192.168.1.50", approvalToken: decided.body.approvalToken })
      .expect(428);
  });

  it("the API refuses a self-approval with 409", async () => {
    const app = await createApp();
    const blocked = await request(app)
      .post("/api/tools/execute")
      .send({ toolId: "zap", target: "192.168.1.50" })
      .expect(428);
    await request(app)
      .post(`/api/approvals/${blocked.body.approvalId}/decision`)
      .send({ decision: "APPROVED", decidedBy: "api-client" })
      .expect(409);
  });
});
