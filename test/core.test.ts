import { describe, it, expect } from "vitest";
import {
  validateStringField,
  addAuditLog,
  auditLogsStore,
  validateSecurityGateway,
} from "../src/server/core/index";

describe("validateStringField", () => {
  it("accepts a valid string", () => {
    expect(validateStringField("hello", "f", 10).valid).toBe(true);
  });
  it("rejects a missing required field", () => {
    expect(validateStringField(undefined, "f", 10, true).valid).toBe(false);
  });
  it("allows a missing optional field", () => {
    expect(validateStringField(undefined, "f", 10, false).valid).toBe(true);
  });
  it("rejects a non-string", () => {
    expect(validateStringField(42, "f", 10).valid).toBe(false);
  });
  it("rejects an over-long value", () => {
    expect(validateStringField("x".repeat(11), "f", 10).valid).toBe(false);
  });
});

describe("addAuditLog", () => {
  it("prepends a log and records a sha256 outputHash when raw output is given", () => {
    const before = auditLogsStore.length;
    const log = addAuditLog("Actor", "ACTION", "127.0.0.1", "OK", "details", "raw-tool-output");
    expect(auditLogsStore.length).toBe(before + 1);
    expect(auditLogsStore[0].id).toBe(log.id);
    expect(log.outputHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
  it("omits outputHash when no raw output is provided", () => {
    const log = addAuditLog("Actor", "ACTION", "127.0.0.1", "OK", "details");
    expect(log.outputHash).toBeUndefined();
  });
});

describe("validateSecurityGateway", () => {
  it("allows an in-scope lab target", () => {
    const d = validateSecurityGateway("192.168.1.50", "nmap");
    expect(d.isAllowed).toBe(true);
    expect(d.scopeValidation).toBe("IN_SCOPE");
  });
  it("denies an explicit out-of-scope target", () => {
    const d = validateSecurityGateway("8.8.8.8", "nmap");
    expect(d.isAllowed).toBe(false);
    expect(d.scopeValidation).toBe("OUT_OF_SCOPE");
  });
  it("flags a high-risk tool for human approval", () => {
    const d = validateSecurityGateway("192.168.1.50", "zap");
    expect(d.isAllowed).toBe(true);
    expect(d.humanApprovalRequired).toBe(true);
  });
});
