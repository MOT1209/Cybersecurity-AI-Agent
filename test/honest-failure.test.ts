import { describe, it, expect, beforeEach, afterAll } from "vitest";

const ORIGINAL_MODE = process.env.SANDBOX_MODE;
afterAll(() => {
  process.env.SANDBOX_MODE = ORIGINAL_MODE;
});

import { executeTool } from "../src/server/sandbox/index";
import { ToolNotAvailableError, ToolNotRegisteredError } from "../src/server/core/errors";
import { listTools, isToolRegistered, hasAdapter } from "../src/server/tools/registry";

describe("tool registry", () => {
  beforeEach(() => {
    process.env.SANDBOX_MODE = "simulate";
  });

  it("separates registered-and-implemented from declared-only tools", () => {
    const tools = listTools();
    const nmap = tools.find((t) => t.descriptor.id === "nmap");
    const zap = tools.find((t) => t.descriptor.id === "zap");
    expect(nmap?.implemented).toBe(true);
    expect(zap?.implemented).toBe(false);
    expect(isToolRegistered("nmap")).toBe(true);
    expect(hasAdapter("zap")).toBe(false);
  });

  it("denies an unregistered tool id outright", async () => {
    await expect(
      executeTool({ toolId: "rm-rf-slash", target: "192.168.1.50" }),
    ).rejects.toBeInstanceOf(ToolNotRegisteredError);
  });
});

describe("honest failure (no fabricated success)", () => {
  it("refuses to run a declared-only tool when simulation was not opted into", async () => {
    process.env.SANDBOX_MODE = "docker"; // no daemon in CI
    await expect(
      executeTool({ toolId: "subfinder", target: "192.168.1.50" }),
    ).rejects.toBeInstanceOf(ToolNotAvailableError);
  });

  it("reports NOT_AVAILABLE with a real reason instead of exit code 0 when no executor exists", async () => {
    process.env.SANDBOX_MODE = "docker"; // no daemon in CI
    const err = await executeTool({ toolId: "nmap", target: "192.168.1.50" }).catch((e) => e);
    expect(err).toBeInstanceOf(ToolNotAvailableError);
    expect((err as ToolNotAvailableError).code).toBe("NOT_AVAILABLE");
    expect(err.message).toMatch(/Docker sandbox is unreachable|no container image/);
    expect(err).not.toHaveProperty("exitCode");
  });

  it("labels simulated output unmistakably when simulation IS opted into", async () => {
    process.env.SANDBOX_MODE = "simulate";
    const res = await executeTool({ toolId: "nmap", target: "192.168.1.50" });
    expect(res.sandbox.mode).toBe("local-sim");
    expect(res.rawOutput).toContain("SIMULATED — NOT A REAL RESULT");
    expect(res.structuredData.simulated).toBe(true);
  });
});
