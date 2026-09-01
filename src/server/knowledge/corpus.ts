/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Corpus ingestion (§24). Chunks the OWASP and MITRE material that already
 * ships in `src/data/cyberData.ts` into retrievable, attributed units.
 *
 * Two deliberate constraints:
 *
 *   - **Seeded, never fetched.** The corpus is built from local data at import
 *     time. Nothing here reaches the network, so retrieval works offline, with
 *     no API key, and cannot silently start returning something different.
 *   - **One field, one chunk.** A chunk is a whole field of a source entry, so
 *     its text is never a fragment stitched out of context, and its citation
 *     names exactly which part of which entry it is.
 *
 * CTF scenarios are deliberately excluded. They carry flags and full solutions:
 * useful to a learner, but nothing an agent should be quoting into a validation
 * rationale or a customer-facing remediation.
 *
 * There is no CWE corpus, because this repository has no CWE text. CWE ids are
 * indexed for exact lookup so a query can find the OWASP entries that reference
 * one — inventing CWE descriptions to fill the gap would be fabrication.
 */

import { OWASP_TOP_10, MITRE_TACTICS } from "../../data/cyberData";
import type { KnowledgeChunk, KnowledgeSource } from "./types";

const OWASP_ORIGIN = "src/data/cyberData.ts#OWASP_TOP_10";
const MITRE_ORIGIN = "src/data/cyberData.ts#MITRE_TACTICS";

function chunk(
  source: KnowledgeSource,
  section: string,
  language: "ar" | "en",
  text: string,
  cwe: string[],
): KnowledgeChunk | null {
  const trimmed = (text ?? "").trim();
  if (!trimmed) return null;
  return {
    id: `${source.kind}:${source.ref}:${section}:${language}`,
    source,
    section,
    language,
    text: trimmed,
    cwe,
    // Language belongs in the citation: the Arabic and English halves of an
    // entry are different text, and a reader must be able to tell which was
    // quoted back to them.
    citation: `${source.kind.toUpperCase()} ${source.ref} — ${source.title} (${section}/${language})`,
  };
}

function buildOwaspChunks(): KnowledgeChunk[] {
  const out: KnowledgeChunk[] = [];
  for (const item of OWASP_TOP_10) {
    const source: KnowledgeSource = {
      kind: "owasp",
      ref: item.code,
      title: item.titleEn,
      origin: `${OWASP_ORIGIN}[${item.id}]`,
    };
    const cwe = [...item.cweList];
    const candidates: [string, "ar" | "en", string][] = [
      ["description", "en", item.descriptionEn],
      ["description", "ar", item.descriptionAr],
      ["impact", "ar", item.impact],
      ["prevention", "ar", item.prevention],
      ["example-fix", "en", item.exampleFixed],
    ];
    for (const [section, language, text] of candidates) {
      const c = chunk(source, section, language, text, cwe);
      if (c) out.push(c);
    }
  }
  return out;
}

function buildMitreChunks(): KnowledgeChunk[] {
  const out: KnowledgeChunk[] = [];
  for (const tactic of MITRE_TACTICS) {
    const tacticSource: KnowledgeSource = {
      kind: "mitre",
      ref: tactic.id,
      title: tactic.nameEn,
      origin: `${MITRE_ORIGIN}[${tactic.id}]`,
    };
    for (const [language, text] of [
      ["en", tactic.descriptionEn],
      ["ar", tactic.descriptionAr],
    ] as const) {
      const c = chunk(tacticSource, "tactic", language, text, []);
      if (c) out.push(c);
    }

    for (const technique of tactic.techniques) {
      const techniqueSource: KnowledgeSource = {
        kind: "mitre",
        ref: technique.id,
        title: technique.name,
        origin: `${MITRE_ORIGIN}[${tactic.id}].techniques[${technique.id}]`,
      };
      // Description and detection stay separate: "how it is done" and "how it
      // is seen" answer different questions and should cite separately.
      const description = chunk(
        techniqueSource,
        "technique",
        "en",
        `${technique.name} (${tactic.nameEn}). ${technique.description}`,
        [],
      );
      const detection = chunk(techniqueSource, "detection", "en", technique.detection, []);
      if (description) out.push(description);
      if (detection) out.push(detection);
    }
  }
  return out;
}

let cached: KnowledgeChunk[] | null = null;

/** The whole corpus, built once. Deterministic and offline. */
export function knowledgeCorpus(): KnowledgeChunk[] {
  if (!cached) cached = [...buildOwaspChunks(), ...buildMitreChunks()];
  return cached;
}

/**
 * Chunks that reference a given CWE id, e.g. "CWE-89". This is an exact index
 * lookup, not a similarity match: an empty result means this corpus says
 * nothing about that CWE, which is a real answer.
 */
export function chunksForCwe(cweId: string): KnowledgeChunk[] {
  const needle = cweId.trim().toUpperCase();
  if (!needle) return [];
  return knowledgeCorpus().filter((c) => c.cwe.some((x) => x.toUpperCase() === needle));
}

/** Every CWE id the corpus can say something about. */
export function indexedCwes(): string[] {
  const set = new Set<string>();
  for (const c of knowledgeCorpus()) for (const id of c.cwe) set.add(id.toUpperCase());
  return [...set].sort();
}

/** Test helper: drop the memoized corpus. */
export function resetCorpus(): void {
  cached = null;
}
