/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Scrapling adapter tests. Pure build/parse unit tests, plus a registry-level
 * check that it is honestly DECLARED ONLY (not silently promoted to
 * "implemented" while its stdout-capture behavior is unverified — see the
 * module doc in src/server/tools/scrapling.ts).
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  buildScraplingRequest,
  parseScraplingOutput,
  summarizeScraplingResult,
  scraplingDescriptor,
  ScraplingParamsSchema,
  SCRAPLING_TOOL_ID,
} from "../src/server/tools/scrapling";
import { hasAdapter, isToolRegistered, listTools } from "../src/server/tools/registry";
import { executeTool, ToolNotAvailableError } from "../src/server/sandbox/index";
import type { ToolRunResult } from "../src/server/sandbox/types";

function fakeResult(rawOutput: string): ToolRunResult {
  return {
    toolId: SCRAPLING_TOOL_ID,
    target: "https://target-corp.lab",
    timestamp: new Date().toISOString(),
    status: "SUCCESS",
    exitCode: 0,
    sandbox: {
      containerId: "test",
      isolated: true,
      cpuLimit: "1",
      memoryLimit: "1024MB",
      network: "test",
      egressBlocked: true,
      workspace: "/tmp/test",
      mode: "docker",
    },
    rawOutput,
    structuredData: {},
  };
}

describe("scrapling adapter — build/parse", () => {
  it("builds a 'get' fetch request writing to /dev/stdout by default", () => {
    const req = buildScraplingRequest("https://target-corp.lab", {});
    expect(req.args).toEqual(["extract", "get", "https://target-corp.lab", "/dev/stdout"]);
    expect(req.toolId).toBe(SCRAPLING_TOOL_ID);
  });

  it("adds --css-selector and --impersonate when provided", () => {
    const req = buildScraplingRequest("https://target-corp.lab", {
      cssSelector: "#content",
      impersonate: "chrome",
    });
    expect(req.args).toContain("--css-selector");
    expect(req.args).toContain("#content");
    expect(req.args).toContain("--impersonate");
    expect(req.args).toContain("chrome");
  });

  it("only adds --solve-cloudflare for stealthy-fetch mode, never as a default", () => {
    const plainGet = buildScraplingRequest("https://target-corp.lab", { solveCloudflare: true });
    expect(plainGet.args).not.toContain("--solve-cloudflare");

    const stealthy = buildScraplingRequest("https://target-corp.lab", {
      mode: "stealthy-fetch",
      solveCloudflare: true,
    });
    expect(stealthy.args).toContain("--solve-cloudflare");
  });

  it("rejects an impersonation string outside the fixed allowlist", () => {
    expect(() => ScraplingParamsSchema.parse({ impersonate: "some-random-string; rm -rf" })).toThrow();
  });

  it("rejects an unknown mode", () => {
    expect(() => ScraplingParamsSchema.parse({ mode: "delete-everything" })).toThrow();
  });

  it("extracts a title and best-effort technology signatures", () => {
    const raw = '<html><head><title>Test Site</title></head><body><div id="wp-content">x</div><script src="jquery-3.6.0.js"></script></body></html>';
    const fp = parseScraplingOutput(raw);
    expect(fp.title).toBe("Test Site");
    expect(fp.technologies).toContain("WordPress");
    expect(fp.technologies).toContain("jQuery");
  });

  it("returns null title and no technologies for unrecognized content, never guesses", () => {
    const fp = parseScraplingOutput("plain text with nothing recognizable");
    expect(fp.title).toBeNull();
    expect(fp.technologies).toEqual([]);
  });

  it("summarizes a full ToolRunResult", () => {
    const res = summarizeScraplingResult(fakeResult("<title>Example</title>"));
    expect(res.structuredData.title).toBe("Example");
  });

  it("is declared MEDIUM risk, network-scoped", () => {
    expect(scraplingDescriptor.riskLevel).toBe("MEDIUM");
    expect(scraplingDescriptor.targetKind).toBe("network");
  });
});

describe("scrapling — honestly declared, not implemented", () => {
  beforeEach(() => {
    process.env.SANDBOX_MODE = "simulate";
  });

  it("is registered but has no adapter", () => {
    expect(isToolRegistered(SCRAPLING_TOOL_ID)).toBe(true);
    expect(hasAdapter(SCRAPLING_TOOL_ID)).toBe(false);
    const entry = listTools().find((t) => t.descriptor.id === SCRAPLING_TOOL_ID);
    expect(entry?.implemented).toBe(false);
  });

  it("refuses to run rather than fabricate a fetch result", async () => {
    process.env.SANDBOX_MODE = "docker";
    const err = await executeTool({ toolId: SCRAPLING_TOOL_ID, target: "192.168.1.50" }).catch((e) => e);
    expect(err).toBeInstanceOf(ToolNotAvailableError);
  });
});
