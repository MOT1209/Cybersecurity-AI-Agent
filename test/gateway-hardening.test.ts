import { describe, it, expect, beforeAll } from "vitest";

beforeAll(() => {
  process.env.SANDBOX_MODE = "local";
  process.env.AI_PROVIDER = "local";
});

import {
  extractHost,
  isIPv4,
  ipInCidr,
  isPrivateOrLabHost,
  matchesScopeEntry,
  validateSecurityGateway,
} from "../src/server/core/index";
import { executeTool, ApprovalRequiredError, GatewayDeniedError } from "../src/server/sandbox/index";

describe("scope primitives", () => {
  it("extracts the bare host from URLs with scheme/port/path", () => {
    expect(extractHost("http://192.168.1.50:8080/api/v1/auth")).toBe("192.168.1.50");
    expect(extractHost("https://APP.target-corp.lab/x")).toBe("app.target-corp.lab");
  });
  it("validates IPv4 and CIDR membership", () => {
    expect(isIPv4("192.168.1.50")).toBe(true);
    expect(isIPv4("192.168.1.50.9")).toBe(false);
    expect(ipInCidr("192.168.1.50", "192.168.0.0/16")).toBe(true);
    expect(ipInCidr("8.8.8.8", "192.168.0.0/16")).toBe(false);
  });
  it("recognizes private/lab hosts only", () => {
    expect(isPrivateOrLabHost("10.0.0.12")).toBe(true);
    expect(isPrivateOrLabHost("app.target-corp.lab")).toBe(true);
    expect(isPrivateOrLabHost("8.8.8.8")).toBe(false);
  });
  it("matches wildcard entries by apex/subdomain, not substring", () => {
    expect(matchesScopeEntry("app.target-corp.lab", "*.target-corp.lab")).toBe(true);
    expect(matchesScopeEntry("target-corp.lab", "*.target-corp.lab")).toBe(true);
    expect(matchesScopeEntry("target-corp.lab.evil.com", "*.target-corp.lab")).toBe(false);
  });
});

describe("security gateway (hardened)", () => {
  it("still allows a legitimate in-scope lab IP", () => {
    expect(validateSecurityGateway("192.168.1.50", "nmap").isAllowed).toBe(true);
  });
  it("still allows an in-scope URL with scheme and port", () => {
    expect(validateSecurityGateway("http://192.168.1.50:8080/api/v1/auth", "nmap").isAllowed).toBe(true);
  });
  it("still denies an explicit out-of-scope host", () => {
    const d = validateSecurityGateway("8.8.8.8", "nmap");
    expect(d.isAllowed).toBe(false);
    expect(d.scopeValidation).toBe("OUT_OF_SCOPE");
  });
  it("closes the substring bypass: '<allowed-ip>.attacker.com' is denied", () => {
    // Previously "192.168.1.50.attacker.com".includes("192.168.1.50") => allowed.
    expect(validateSecurityGateway("192.168.1.50.attacker.com", "nmap").isAllowed).toBe(false);
  });
  it("denies an out-of-scope host even when smuggled inside a longer string", () => {
    expect(validateSecurityGateway("8.8.8.8.nip.io", "nmap").isAllowed).toBe(false);
  });
});

describe("human-approval enforcement", () => {
  it("blocks a high-risk tool without approval (throws ApprovalRequiredError)", async () => {
    await expect(
      executeTool({ toolId: "zap", target: "192.168.1.50" }),
    ).rejects.toBeInstanceOf(ApprovalRequiredError);
  });
  it("runs the high-risk tool once approval is granted", async () => {
    const res = await executeTool({ toolId: "zap", target: "192.168.1.50", approved: true });
    expect(res.status).toBe("SUCCESS");
  });
  it("still denies a high-risk tool out of scope regardless of approval", async () => {
    await expect(
      executeTool({ toolId: "zap", target: "8.8.8.8", approved: true }),
    ).rejects.toBeInstanceOf(GatewayDeniedError);
  });
});
