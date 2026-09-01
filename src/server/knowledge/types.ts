/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Knowledge base contract (§24).
 *
 * The governing rule of this module: **a chunk cannot exist without its
 * source.** Provenance is part of the type, not an optional decoration, so
 * there is no code path that hands an agent a claim it cannot attribute.
 * Knowledge without provenance is the same failure class as a finding without
 * evidence — it is an assertion the platform cannot back up.
 */

export type KnowledgeSourceKind = "owasp" | "mitre";

export interface KnowledgeSource {
  kind: KnowledgeSourceKind;
  /** Stable identifier inside its framework, e.g. "A03:2021" or "T1595". */
  ref: string;
  title: string;
  /**
   * Where the text physically came from in this repository. The corpus is
   * seeded from local data and never fetched at runtime, so every chunk can be
   * traced back to a file a reviewer can open.
   */
  origin: string;
}

export interface KnowledgeChunk {
  id: string;
  source: KnowledgeSource;
  /** Which part of the entry this text is, e.g. "description", "prevention". */
  section: string;
  language: "ar" | "en";
  text: string;
  /** CWE identifiers this chunk speaks to, for exact lookup. */
  cwe: string[];
  /** Rendered attribution, carried with the text wherever it travels. */
  citation: string;
}

export interface RetrievedChunk {
  chunk: KnowledgeChunk;
  /** BM25 score plus any exact-identifier boost. Higher is more relevant. */
  score: number;
  /** The query terms that actually matched — why this chunk was returned. */
  matchedTerms: string[];
}

export interface RetrieveOptions {
  limit?: number;
  kinds?: KnowledgeSourceKind[];
  /** Exact CWE identifiers to prefer, e.g. ["CWE-89"]. */
  cwe?: string[];
  /**
   * Chunks scoring below this are not returned. Returning nothing is a valid,
   * honest answer: a weak lexical match dressed up as a citation is worse than
   * no citation at all.
   */
  minScore?: number;
}
