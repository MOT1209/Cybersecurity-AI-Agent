/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * ZAP + volatility adapter tests. Pure build/parse unit tests — no Docker, no
 * network, no memory image. The fixtures below are representative samples of
 * zap-baseline.py summary output and the Volatility 3 JSON renderer, stated
 * as such; they pin the parser, not the upstream tools.
 */

import { describe, it, expect } from "vitest";
import {
  buildZapRequest,
  parseZapOutput,
  summarizeZapResult,
  zapDescriptor,
  ZapParamsSchema,
} from "../src/server/tools/zap";
import {
  buildVolatilityRequest,
  parseVolatilityOutput,
  summarizeVolatilityResult,
  volatilityDescriptor,
  MAX_VOLATILITY_ROWS,
  VolatilityParamsSchema,
} from "../src/server/tools/volatility";
import type { ToolRunResult } from "../src/server/sandbox/types";

function fakeResult(rawOutput: string, toolId: string): ToolRunResult {
  return {
    toolId,
    target: "test-target",
    timestamp: new Date().toISOString(),
    status: "SUCCESS",
    exitCode: 0,
    sandbox: {
      containerId: "test",
      isolated: true,
      cpuLimit: "1",
      memoryLimit: "512MB",
      network: "test",
      egressBlocked: true,
      workspace: "/tmp/test",
      mode: "docker",
    },
    rawOutput,
    structuredData: {},
  };
}

describe("zap adapter", () => {
  it("builds a baseline scan with a capped spider duration", () => {
    const req = buildZapRequest("https://target-corp.lab", {});
    expect(req.args).toEqual(["zap-baseline.py", "-t", "https://target-corp.lab", "-m", "2"]);
    expect(req.toolId).toBe("zap");
    expect(buildZapRequest("https://target-corp.lab", { spiderMinutes: 10 }).args).toContain("10");
  });

  it("rejects a spider duration outside the cap", () => {
    expect(() => ZapParamsSchema.parse({ spiderMinutes: 0 })).toThrow();
    expect(() => ZapParamsSchema.parse({ spiderMinutes: 31 })).toThrow();
    expect(() => buildZapRequest("https://target-corp.lab", { spiderMinutes: 999 })).toThrow();
  });

  it("parses WARN-NEW and FAIL-NEW summary lines into alerts", () => {
    const raw = [
      "2026-01-01 INFO: some progress chatter",
      "WARN-NEW: Storable and Cacheable Content [10049] x 32",
      "    https://target-corp.lab/static/app.js",
      "FAIL-NEW: SQL Injection [40018] x 2",
      "WARN-INPROG: Content Security Policy Header Missing [10038] x 1",
      "FAIL-NEW: 1\tWARN-NEW: 21\tWARN-INPROG: 1",
    ].join("\n");
    const alerts = parseZapOutput(raw);
    expect(alerts).toHaveLength(3);
    expect(alerts[0]).toMatchObject({ severity: "WARN", state: "NEW", name: "Storable and Cacheable Content", pluginId: "10049", occurrences: 32 });
    expect(alerts[1]).toMatchObject({ severity: "FAIL", state: "NEW", pluginId: "40018", occurrences: 2 });
    expect(alerts[2].state).toBe("INPROG");
  });

  it("returns no alerts for output without summary lines, never 'clean'", () => {
    expect(parseZapOutput("")).toEqual([]);
    expect(parseZapOutput("INFO: scan finished, nothing printed")).toEqual([]);
  });

  it("counts only NEW alerts as findings", () => {
    const res = summarizeZapResult(
      fakeResult("FAIL-NEW: SQL Injection [40018] x 1\nWARN-INPROG: Old News [10038] x 5", "zap"),
    );
    expect(res.structuredData.newAlertCount).toBe(1);
    expect(res.structuredData.failCount).toBe(1);
    expect(res.structuredData.warnCount).toBe(0);
  });

  it("is declared HIGH risk, network-scoped and approval-gated by the gateway", () => {
    expect(zapDescriptor.riskLevel).toBe("HIGH");
    expect(zapDescriptor.targetKind).toBe("network");
    expect(zapDescriptor.needsNetwork).toBe(true);
    expect(zapDescriptor.timeoutMs).toBeGreaterThan(0);
  });
});

describe("volatility adapter", () => {
  it("builds a JSON-renderer run over the contained image path", () => {
    const req = buildVolatilityRequest("/workspace/mem.raw", {});
    expect(req.args).toEqual(["vol", "--renderer", "json", "-f", "/workspace/mem.raw", "windows.pslist"]);
    expect(req.toolId).toBe("volatility");
    expect(buildVolatilityRequest("/workspace/dump.vmem", { plugin: "windows.netscan" }).args).toContain("windows.netscan");
  });

  it("rejects plugins outside the allowlist and non-image targets", () => {
    expect(() => VolatilityParamsSchema.parse({ plugin: "windows.mimikatz" })).toThrow();
    expect(() => buildVolatilityRequest("/workspace/notes.txt", {})).toThrow(/memory image/);
    expect(() => buildVolatilityRequest("/workspace/archive.zip", {})).toThrow(/memory image/);
  });

  it("parses the JSON renderer document into column-mapped rows", () => {
    const raw = JSON.stringify({
      columns: ["PID", "Process", "PPID"],
      rows: [[4, "System", 0], [232, "svchost.exe", 4]],
    });
    const parsed = parseVolatilityOutput(`volatility banner line\n${raw}`);
    expect(parsed.columns).toEqual(["PID", "Process", "PPID"]);
    expect(parsed.rows).toEqual([
      { PID: 4, Process: "System", PPID: 0 },
      { PID: 232, Process: "svchost.exe", PPID: 4 },
    ]);
    expect(parsed.truncated).toBe(false);
  });

  it("caps rows so one image cannot flood the findings store", () => {
    const raw = JSON.stringify({
      columns: ["PID"],
      rows: Array.from({ length: MAX_VOLATILITY_ROWS + 50 }, (_, i) => [i]),
    });
    const parsed = parseVolatilityOutput(raw);
    expect(parsed.rows).toHaveLength(MAX_VOLATILITY_ROWS);
    expect(parsed.truncated).toBe(true);
  });

  it("returns empty for unparseable output, never 'clean'", () => {
    expect(parseVolatilityOutput("")).toEqual({ columns: [], rows: [], truncated: false });
    expect(parseVolatilityOutput("Traceback (most recent call last): boom").rows).toEqual([]);
  });

  it("summarizes row counts onto the result", () => {
    const raw = JSON.stringify({ columns: ["PID"], rows: [[1], [2], [3]] });
    const res = summarizeVolatilityResult(fakeResult(raw, "volatility"));
    expect(res.structuredData.rowCount).toBe(3);
    expect(res.structuredData.truncated).toBe(false);
  });

  it("is declared LOW risk, offline and filesystem-contained", () => {
    expect(volatilityDescriptor.riskLevel).toBe("LOW");
    expect(volatilityDescriptor.needsNetwork).toBe(false);
    expect(volatilityDescriptor.targetKind).toBe("filesystem");
    expect(volatilityDescriptor.filesystemAccess).toBe("workspace-ro");
  });
});
