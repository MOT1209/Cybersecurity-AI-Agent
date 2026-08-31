import { describe, it, expect } from "vitest";
import {
  buildSubfinderRequest,
  parseSubfinderOutput,
  SubfinderParamsSchema,
} from "../src/server/tools/subfinder";
import {
  buildNucleiRequest,
  parseNucleiOutput,
  NucleiParamsSchema,
} from "../src/server/tools/nuclei";

describe("subfinder adapter", () => {
  it("normalizes a URL target down to its registrable domain", () => {
    const req = buildSubfinderRequest("https://target-corp.lab:8443/admin", {});
    expect(req.args.slice(0, 2)).toEqual(["-d", "target-corp.lab"]);
    expect(req.target).toBe("target-corp.lab");
  });

  it("is passive by default and only adds -active on request", () => {
    expect(buildSubfinderRequest("target-corp.lab", {}).args).not.toContain("-active");
    expect(
      buildSubfinderRequest("target-corp.lab", { activeResolution: true }).args,
    ).toContain("-active");
  });

  it("rejects an IP, a bare hostname and shell metacharacters", () => {
    expect(() => buildSubfinderRequest("192.168.1.50", {})).toThrow(/registrable domain/);
    expect(() => buildSubfinderRequest("localhost", {})).toThrow(/registrable domain/);
    expect(() => buildSubfinderRequest("evil.lab; rm -rf /", {})).toThrow();
  });

  it("rejects an out-of-range maxResults", () => {
    expect(() => SubfinderParamsSchema.parse({ maxResults: 99999 })).toThrow();
  });

  it("parses JSONL, deduplicates and skips malformed lines", () => {
    const raw = [
      '{"host":"api.target-corp.lab","source":"crtsh"}',
      "not json at all",
      '{"host":"API.target-corp.lab"}',
      '{"nohost":true}',
      '{"host":"vpn.target-corp.lab","source":"dnsdumpster"}',
    ].join("\n");
    const subs = parseSubfinderOutput(raw);
    expect(subs.map((s) => s.host)).toEqual(["api.target-corp.lab", "vpn.target-corp.lab"]);
    expect(subs[0].source).toBe("crtsh");
  });

  it("honors the result cap", () => {
    const raw = Array.from({ length: 50 }, (_, i) => `{"host":"h${i}.target-corp.lab"}`).join("\n");
    expect(parseSubfinderOutput(raw, 10)).toHaveLength(10);
  });
});

describe("nuclei adapter", () => {
  it("refuses intrusive template groups that were never allowlisted", () => {
    expect(() => NucleiParamsSchema.parse({ tags: ["dos"] })).toThrow();
    expect(() => NucleiParamsSchema.parse({ tags: ["fuzzing"] })).toThrow();
    expect(() => NucleiParamsSchema.parse({ tags: ["cve"] })).not.toThrow();
  });

  it("caps rate limit and concurrency so a scan cannot become a flood", () => {
    expect(() => NucleiParamsSchema.parse({ rateLimit: 10000 })).toThrow();
    expect(() => NucleiParamsSchema.parse({ concurrency: 500 })).toThrow();
  });

  it("disables out-of-band callbacks and update checks in the argv", () => {
    const args = buildNucleiRequest("http://192.168.1.50:8080", {}).args;
    expect(args).toContain("-no-interactsh");
    expect(args).toContain("-disable-update-check");
    expect(args).toContain("-jsonl");
  });

  it("parses JSONL detections with classification metadata", () => {
    const raw = [
      JSON.stringify({
        "template-id": "CVE-2021-44228",
        type: "http",
        "matched-at": "http://192.168.1.50:8080/",
        info: {
          name: "Apache Log4j RCE",
          severity: "CRITICAL",
          description: "log4shell",
          classification: { "cve-id": ["CVE-2021-44228"], "cwe-id": ["CWE-502"] },
        },
      }),
      "garbage",
      JSON.stringify({ info: { name: "no template id" } }),
    ].join("\n");
    const d = parseNucleiOutput(raw);
    expect(d).toHaveLength(1);
    expect(d[0].severity).toBe("critical");
    expect(d[0].cve).toEqual(["CVE-2021-44228"]);
    expect(d[0].cwe).toEqual(["CWE-502"]);
  });

  it("marks every detection unvalidated — a scanner hit is not a vulnerability", () => {
    const raw = JSON.stringify({ "template-id": "x", info: { name: "x", severity: "high" } });
    expect(parseNucleiOutput(raw)[0].validated).toBe(false);
  });
});
