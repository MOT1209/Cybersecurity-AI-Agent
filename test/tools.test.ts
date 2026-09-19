import { describe, it, expect, beforeAll } from "vitest";

beforeAll(() => {
  process.env.SANDBOX_MODE = "local";
  process.env.AI_PROVIDER = "local";
});

import { executeTool, ApprovalRequiredError } from "../src/server/sandbox/index";
import {
  buildNucleiRequest,
  parseNucleiOutput,
} from "../src/server/tools/nuclei";
import {
  buildWfuzzRequest,
  parseWfuzzOutput,
} from "../src/server/tools/wfuzz";
import {
  buildTheHarvesterRequest,
  parseTheHarvesterOutput,
} from "../src/server/tools/theharvester";
import { buildCtfrRequest, parseCtfrOutput } from "../src/server/tools/ctfr";
import { buildSqlmapRequest, parseSqlmapOutput } from "../src/server/tools/sqlmap";
import { buildXsstrikeRequest, parseXsstrikeOutput } from "../src/server/tools/xsstrike";
import { ToolInputError } from "../src/server/tools/errors";

describe("nuclei adapter", () => {
  it("builds a jsonl scan request with the target and severity filter", () => {
    const req = buildNucleiRequest("http://192.168.1.50", { severity: "critical,high" });
    expect(req.args).toEqual([
      "-u",
      "http://192.168.1.50",
      "-severity",
      "critical,high",
      "-rate-limit",
      "50",
      "-jsonl",
      "-silent",
    ]);
  });

  it("rejects an invalid severity value", () => {
    expect(() => buildNucleiRequest("192.168.1.50", { severity: "extreme" })).toThrow();
  });

  it("parses JSONL findings", () => {
    const raw = '{"template-id":"exposed-panel","info":{"severity":"high"},"matched-at":"192.168.1.50:80"}\nnoise line';
    const findings = parseNucleiOutput(raw);
    expect(findings).toEqual([{ templateId: "exposed-panel", severity: "high", matchedAt: "192.168.1.50:80" }]);
  });
});

describe("wfuzz adapter", () => {
  it("requires a FUZZ placeholder in the target", () => {
    expect(() => buildWfuzzRequest("http://192.168.1.50/path", {})).toThrow(ToolInputError);
  });

  it("builds an argument vector with the wordlist and target last", () => {
    const req = buildWfuzzRequest("http://192.168.1.50/FUZZ", { wordlist: "common", hideCodes: "404" });
    expect(req.args[req.args.length - 1]).toBe("http://192.168.1.50/FUZZ");
    expect(req.args).toContain("--hc");
  });

  it("parses table rows", () => {
    const raw = '000001:  C=200    12 L     34 W     567 Ch   "admin"';
    expect(parseWfuzzOutput(raw)).toEqual([{ id: 1, statusCode: 200, payload: "admin" }]);
  });
});

describe("theHarvester adapter", () => {
  it("rejects a non-domain target", () => {
    expect(() => buildTheHarvesterRequest("192.168.1.50", {})).toThrow(ToolInputError);
  });

  it("builds a domain enumeration request", () => {
    const req = buildTheHarvesterRequest("Target-Corp.LAB", { source: "crtsh" });
    expect(req.target).toBe("target-corp.lab");
    expect(req.args).toEqual(["-d", "target-corp.lab", "-b", "crtsh", "-l", "200"]);
  });

  it("extracts emails and hosts from raw output", () => {
    const raw = "Found: admin@target-corp.lab\nHost: mail.target-corp.lab";
    const { emails, hosts } = parseTheHarvesterOutput(raw);
    expect(emails).toContain("admin@target-corp.lab");
    expect(hosts).toContain("mail.target-corp.lab");
  });
});

describe("ctfr adapter", () => {
  it("rejects a non-domain target", () => {
    expect(() => buildCtfrRequest("not a domain")).toThrow(ToolInputError);
  });

  it("writes to /dev/stdout instead of a file (read-only sandbox fs)", () => {
    const req = buildCtfrRequest("target-corp.lab");
    expect(req.args).toEqual(["-d", "target-corp.lab", "-o", "/dev/stdout"]);
  });

  it("dedupes parsed subdomains", () => {
    const raw = "app.target-corp.lab\napp.target-corp.lab\nmail.target-corp.lab";
    expect(parseCtfrOutput(raw)).toEqual(["app.target-corp.lab", "mail.target-corp.lab"]);
  });
});

describe("sqlmap adapter (high-risk)", () => {
  it("caps level/risk below sqlmap's own maximums by default", () => {
    const req = buildSqlmapRequest("http://192.168.1.50/item?id=1", {});
    expect(req.args).toEqual(["-u", "http://192.168.1.50/item?id=1", "--batch", "--level", "1", "--risk", "1"]);
  });

  it("rejects a risk level above the platform cap", () => {
    expect(() => buildSqlmapRequest("http://192.168.1.50", { risk: 3 })).toThrow();
  });

  it("requires human approval via the security gateway", async () => {
    await expect(
      executeTool({ toolId: "sqlmap", target: "192.168.1.50", args: ["-u", "192.168.1.50", "--batch"] }),
    ).rejects.toBeInstanceOf(ApprovalRequiredError);
  });

  it("parses injectable-parameter banners", () => {
    const raw = "Parameter: id (GET)\n    Type: boolean-based blind";
    expect(parseSqlmapOutput(raw)).toEqual([{ parameter: "id", type: "GET", title: "Injectable parameter: id" }]);
  });
});

describe("XSStrike adapter (high-risk)", () => {
  it("builds a non-interactive scan request", () => {
    const req = buildXsstrikeRequest("http://192.168.1.50/search?q=1", {});
    expect(req.args).toEqual(["-u", "http://192.168.1.50/search?q=1", "--skip"]);
  });

  it("requires human approval via the security gateway", async () => {
    await expect(
      executeTool({ toolId: "xsstrike", target: "192.168.1.50", args: ["-u", "192.168.1.50", "--skip"] }),
    ).rejects.toBeInstanceOf(ApprovalRequiredError);
  });

  it("parses reflected payload findings", () => {
    const raw = "Payload: <script>alert(1)</script>";
    expect(parseXsstrikeOutput(raw)).toEqual([{ payload: "<script>alert(1)</script>", context: "reflected" }]);
  });
});
