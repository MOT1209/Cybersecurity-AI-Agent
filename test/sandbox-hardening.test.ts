import { describe, it, expect, beforeAll } from "vitest";

beforeAll(() => {
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
});

import { executeTool } from "../src/server/sandbox/index";
import { networkModeFor, allowEgress, SANDBOX_NETWORK_NAME } from "../src/server/sandbox/network";
import { getToolDescriptor, listTools } from "../src/server/tools/registry";

describe("sandbox network policy", () => {
  it("uses a dedicated sandbox network, never the host default bridge", () => {
    expect(SANDBOX_NETWORK_NAME).not.toBe("bridge");
  });

  it("blocks egress unless the operator explicitly allows it", () => {
    delete process.env.SANDBOX_ALLOW_EGRESS;
    expect(allowEgress()).toBe(false);
    process.env.SANDBOX_ALLOW_EGRESS = "true";
    expect(allowEgress()).toBe(true);
    delete process.env.SANDBOX_ALLOW_EGRESS;
  });

  it("gives offline tools no network interface at all", () => {
    expect(networkModeFor(false)).toBe("none");
    expect(networkModeFor(true)).toBe("isolated");
  });

  it("marks code/filesystem scanners as not needing the network", () => {
    for (const id of ["semgrep", "trivy", "volatility"]) {
      expect(getToolDescriptor(id)!.needsNetwork).toBe(false);
    }
    expect(getToolDescriptor("nmap")!.needsNetwork).toBe(true);
  });
});

describe("resource limits", () => {
  it("every registered tool declares a bounded ceiling and timeout", () => {
    for (const { descriptor } of listTools()) {
      expect(descriptor.resourceLimits.memoryMb).toBeGreaterThan(0);
      expect(descriptor.resourceLimits.cpus).toBeGreaterThan(0);
      expect(descriptor.resourceLimits.pids).toBeGreaterThan(0);
      expect(descriptor.timeoutMs).toBeGreaterThan(0);
    }
  });

  it("a caller cannot widen a tool's declared timeout", async () => {
    const declared = getToolDescriptor("nmap")!.timeoutMs;
    const res = await executeTool({
      toolId: "nmap",
      target: "192.168.1.50",
      timeoutMs: declared * 100,
    });
    expect(res.structuredData.timeoutMs).toBe(declared);
  });

  it("reports the sandbox posture on every run", async () => {
    const res = await executeTool({ toolId: "nmap", target: "192.168.1.50" });
    expect(res.sandbox.isolated).toBe(true);
    expect(res.sandbox.egressBlocked).toBe(true);
    expect(res.sandbox.workspace).toContain("/tmp/cyberguard");
  });
});
