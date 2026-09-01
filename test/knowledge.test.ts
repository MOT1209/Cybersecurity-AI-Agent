import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import fs from "fs";
import path from "path";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
});

import {
  knowledgeCorpus,
  chunksForCwe,
  indexedCwes,
  retrieve,
  retrieveForFinding,
  citationsFor,
  formatForPrompt,
  tokenize,
  DEFAULT_MIN_SCORE,
} from "../src/server/knowledge";
import { validationAgent, assessEvidence } from "../src/server/agents/validation/agent";
import { remediationAgent, baselineRemediation } from "../src/server/agents/remediation/agent";
import {
  fromNmapPorts,
  fromSemgrepFindings,
  recordFindings,
  listFindings,
  resetFindings,
} from "../src/server/findings/engine";

describe("corpus provenance", () => {
  it("gives every chunk a source, an origin and a citation", () => {
    const corpus = knowledgeCorpus();
    expect(corpus.length).toBeGreaterThan(0);
    for (const c of corpus) {
      expect(c.text.trim().length).toBeGreaterThan(0);
      expect(c.source.ref).toBeTruthy();
      expect(c.source.title).toBeTruthy();
      // The origin must point at a file a reviewer can actually open.
      expect(c.source.origin).toMatch(/^src\/data\/cyberData\.ts#/);
      expect(c.citation).toContain(c.source.ref);
      expect(c.citation).toContain(c.section);
    }
  });

  it("points every origin at a file that exists", () => {
    const files = new Set(knowledgeCorpus().map((c) => c.source.origin.split("#")[0]));
    for (const f of files) {
      expect(fs.existsSync(path.join(process.cwd(), f)), `${f} must exist`).toBe(true);
    }
  });

  it("gives each chunk a unique id", () => {
    const ids = knowledgeCorpus().map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("excludes CTF scenarios, which carry flags and full solutions", () => {
    const text = knowledgeCorpus().map((c) => c.text).join("\n");
    expect(text).not.toMatch(/CYBERGUARD\{/i);
    expect(knowledgeCorpus().every((c) => c.source.kind === "owasp" || c.source.kind === "mitre")).toBe(true);
  });

  it("indexes CWE ids for exact lookup without inventing CWE text", () => {
    expect(indexedCwes()).toContain("CWE-89");
    const hits = chunksForCwe("CWE-89");
    expect(hits.length).toBeGreaterThan(0);
    // Every hit is a real OWASP entry that references the CWE — the corpus does
    // not carry a fabricated description of the CWE itself.
    for (const h of hits) expect(h.source.kind).toBe("owasp");
    expect(chunksForCwe("CWE-99999")).toEqual([]);
  });
});

describe("retrieval", () => {
  it("finds the injection entry for a SQL injection query, with its citation", () => {
    const hits = retrieve("SQL injection in a login form");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].chunk.source.ref).toBe("A03:2021");
    expect(hits[0].chunk.citation).toContain("A03:2021");
    expect(hits[0].matchedTerms).toContain("injection");
  });

  it("returns nothing rather than the least-bad paragraph", () => {
    // Nothing in a security corpus answers these. An empty result is the
    // honest answer; a citation here would be authority the retriever has not
    // earned.
    expect(retrieve("pizza recipe with extra cheese")).toEqual([]);
    expect(retrieve("the quick brown fox jumps over a lazy dog")).toEqual([]);
  });

  it("does not match on a single common word alone", () => {
    // "known" appears in the corpus, but a four-term query overlapping on one
    // word is a coincidence, not a match.
    const hits = retrieve("outdated dependency with a known CVE");
    for (const h of hits) expect(h.matchedTerms.length).toBeGreaterThan(1);
  });

  it("looks up an exact identifier", () => {
    const byCwe = retrieve("CWE-89");
    expect(byCwe.length).toBeGreaterThan(0);
    expect(byCwe.every((h) => h.chunk.cwe.includes("CWE-89"))).toBe(true);

    const byTechnique = retrieve("T1595");
    expect(byTechnique.length).toBeGreaterThan(0);
    expect(byTechnique[0].chunk.source.ref).toBe("T1595");
  });

  it("retrieves Arabic text for an Arabic query", () => {
    const hits = retrieve("حقن الأوامر");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.some((h) => h.chunk.language === "ar")).toBe(true);
  });

  it("filters by source kind", () => {
    const hits = retrieve("scanning ports and network services", { kinds: ["mitre"] });
    expect(hits.every((h) => h.chunk.source.kind === "mitre")).toBe(true);
  });

  it("honors the result limit and orders by score", () => {
    const hits = retrieve("injection", { limit: 2, minScore: 0 });
    expect(hits.length).toBeLessThanOrEqual(2);
    for (let i = 1; i < hits.length; i++) {
      expect(hits[i - 1].score).toBeGreaterThanOrEqual(hits[i].score);
    }
  });

  it("drops everything below the score floor", () => {
    const generous = retrieve("injection", { minScore: 0 });
    const strict = retrieve("injection", { minScore: 1000 });
    expect(generous.length).toBeGreaterThan(0);
    expect(strict).toEqual([]);
    expect(DEFAULT_MIN_SCORE).toBeGreaterThan(0);
  });

  it("ignores stopwords in both the query and the index", () => {
    expect(tokenize("the injection of a payload")).toEqual(["injection", "payload"]);
    expect(tokenize("في الحقن")).toEqual(["الحقن"]);
  });

  it("keeps identifiers intact when tokenizing", () => {
    expect(tokenize("CWE-89 and A03:2021")).toEqual(["cwe-89", "a03:2021"]);
  });
});

describe("every retrieved chunk can be attributed", () => {
  it("renders a citation and an origin into the prompt block", () => {
    const hits = retrieve("injection");
    const prompt = formatForPrompt(hits);
    for (const h of hits) {
      expect(prompt).toContain(h.chunk.citation);
      expect(prompt).toContain(h.chunk.source.origin);
    }
    // Reference material is labelled as such, so it can never be read back as
    // an observation of a target.
    expect(prompt).toContain("[REFERENCE");
  });

  it("says so plainly when nothing matched", () => {
    expect(formatForPrompt([])).toMatch(/No reference material/i);
    expect(citationsFor([])).toEqual([]);
  });

  it("de-duplicates citations while preserving order", () => {
    const hits = retrieve("injection", { minScore: 0, limit: 10 });
    const cites = citationsFor(hits);
    expect(new Set(cites).size).toBe(cites.length);
  });
});

describe("knowledge is context, never evidence", () => {
  beforeEach(() => resetFindings());

  it("does not change what the deterministic assessment concludes", async () => {
    // A semgrep finding carrying CWE-89 retrieves plenty of reference material
    // about injection. None of it may move the verdict: the evidence is still
    // one inferential match.
    const [finding] = recordFindings(fromSemgrepFindings(
      [
        {
          ruleId: "javascript.sql.injection",
          path: "src/db.ts",
          startLine: 12,
          endLine: 12,
          message: "SQL injection",
          severity: "ERROR",
          cwe: ["CWE-89"],
          owasp: [],
          validated: false,
        },
      ],
      { projectId: "proj_alpha_lab", target: "src/db.ts", agentId: "code", toolId: "semgrep", traceId: "t-know" },
    ));

    const retrievedForIt = retrieveForFinding({ title: finding.title, cwe: finding.cwe });
    expect(retrievedForIt.length).toBeGreaterThan(0); // material really is available

    const assessment = assessEvidence(finding, "proj_alpha_lab");
    expect(assessment.status).toBe("UNCONFIRMED");

    const res = await validationAgent.run({ findingIds: [finding.id], projectId: "proj_alpha_lab" });
    const verdict = res.data!.verdicts[0];
    // Identical to the evidence-only assessment: the corpus contributed nothing.
    expect(verdict.status).toBe(assessment.status);
    expect(verdict.confidence).toBe(assessment.confidence);
  });

  it("records what it consulted, with sources", async () => {
    const [finding] = recordFindings(fromNmapPorts(
      [{ port: 22, protocol: "tcp", state: "open", service: "ssh" }],
      { projectId: "proj_alpha_lab", target: "192.168.1.50", agentId: "recon", toolId: "nmap", traceId: "t-know2" },
    ));
    const res = await validationAgent.run({ findingIds: [finding.id], projectId: "proj_alpha_lab" });
    expect(Array.isArray(res.data!.knowledgeCitations)).toBe(true);
    for (const c of res.data!.knowledgeCitations) expect(c).toMatch(/^(OWASP|MITRE) /);
  });
});

describe("remediation cites what it was written against", () => {
  beforeEach(() => resetFindings());

  it("attaches only citations the retriever actually produced", async () => {
    const [finding] = recordFindings(fromSemgrepFindings(
      [
        {
          ruleId: "javascript.sql.injection",
          path: "src/db.ts",
          startLine: 4,
          endLine: 4,
          message: "SQL injection",
          severity: "ERROR",
          cwe: ["CWE-89"],
          owasp: [],
          validated: false,
        },
      ],
      { projectId: "proj_alpha_lab", target: "src/db.ts", agentId: "code", toolId: "semgrep", traceId: "t-rem" },
    ));

    const res = await remediationAgent.run({ findingIds: [finding.id], projectId: "proj_alpha_lab" });
    const refs = res.data!.entries[0].remediation.references ?? [];
    expect(refs.length).toBeGreaterThan(0);

    // Each citation must correspond to a real chunk in the corpus.
    const known = new Set(knowledgeCorpus().map((c) => c.citation));
    for (const r of refs) expect(known.has(r)).toBe(true);
  });

  it("carries an empty reference list rather than an invented source", () => {
    const [finding] = recordFindings(fromNmapPorts(
      [{ port: 4444, protocol: "tcp", state: "open", service: "unknown" }],
      { projectId: "proj_alpha_lab", target: "192.168.1.50", agentId: "recon", toolId: "nmap", traceId: "t-rem2" },
    ));
    // Called with no retrieved material, exactly as it would be when the corpus
    // has nothing to say.
    const remediation = baselineRemediation(finding);
    expect(remediation.references).toEqual([]);
    expect(remediation.summary.length).toBeGreaterThan(0);
    expect(listFindings({ traceId: "t-rem2" })).toHaveLength(1);
  });
});
