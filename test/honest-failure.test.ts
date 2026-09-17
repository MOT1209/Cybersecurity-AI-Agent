import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

/**
 * The honest-failure contract must hold on EVERY machine — including one where a
 * Docker daemon is running.
 *
 * This file used to prove it by borrowing the environment: it set
 * SANDBOX_MODE=docker under a "// no daemon in CI" comment and asserted that the
 * tool could not run. That made the signal inverted — the tests passed where
 * Docker was ABSENT and failed on a developer's laptop where Docker was PRESENT,
 * because execution then fell through to a real container run (and a real image
 * pull over the network) instead of the refusal under test. A guarantee that is
 * only verified where the capability is missing is not verified.
 *
 * So the unreachable daemon is now injected explicitly, via a stub client whose
 * `ping()` rejects. Everything else exercised below is the real code path:
 * the real `DockerExecutor.isAvailable()` probe, its deadline/catch logic, and
 * the real `resolveExecutor()` refusal in `sandbox/index.ts`.
 */
vi.mock("dockerode", () => {
  class UnreachableDocker {
    ping(): Promise<void> {
      return Promise.reject(new Error("connect ENOENT /var/run/docker.sock"));
    }
  }
  return { default: UnreachableDocker };
});

const ORIGINAL_MODE = process.env.SANDBOX_MODE;
// Restored after every test, not left for the next one to overwrite.
afterEach(() => {
  // Assigning `undefined` would set the literal string "undefined", leaking a
  // bogus mode into any later test file in the same worker.
  if (ORIGINAL_MODE === undefined) delete process.env.SANDBOX_MODE;
  else process.env.SANDBOX_MODE = ORIGINAL_MODE;
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
    process.env.SANDBOX_MODE = "docker";
    // The premise of this test: a tool the registry declares but cannot run.
    // Asserted, not assumed — if an adapter lands, this test must fail and be
    // rewritten rather than quietly stop testing the refusal.
    expect(hasAdapter("prowler")).toBe(false);

    const err = await executeTool({ toolId: "prowler", target: "192.168.1.50" }).catch((e) => e);

    expect(err).toBeInstanceOf(ToolNotAvailableError);
    expect((err as ToolNotAvailableError).code).toBe("NOT_AVAILABLE");
    expect(err.message).toMatch(/no implemented adapter/);
    // The point of the contract: a refusal carries no execution result at all.
    expect(err).not.toHaveProperty("exitCode");
    expect(err).not.toHaveProperty("rawOutput");
  });

  it("reports NOT_AVAILABLE with a real reason instead of exit code 0 when no executor exists", async () => {
    process.env.SANDBOX_MODE = "docker";
    // An implemented tool is required here: the unavailable-executor branch is
    // only reachable once the registry admits it *could* have run this.
    expect(hasAdapter("nmap")).toBe(true);

    const err = await executeTool({ toolId: "nmap", target: "192.168.1.50" }).catch((e) => e);

    expect(err).toBeInstanceOf(ToolNotAvailableError);
    expect((err as ToolNotAvailableError).code).toBe("NOT_AVAILABLE");
    expect(err.message).toMatch(/Docker sandbox is unreachable/);
    expect(err).not.toHaveProperty("exitCode");
    expect(err).not.toHaveProperty("rawOutput");
  });

  it("labels simulated output unmistakably when simulation IS opted into", async () => {
    process.env.SANDBOX_MODE = "simulate";
    const res = await executeTool({ toolId: "nmap", target: "192.168.1.50" });
    expect(res.sandbox.mode).toBe("local-sim");
    expect(res.rawOutput).toContain("SIMULATED — NOT A REAL RESULT");
    expect(res.structuredData.simulated).toBe(true);
  });
});
