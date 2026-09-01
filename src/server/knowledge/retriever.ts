/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Retrieval over the security corpus (§24).
 *
 * BM25 over locally-built chunks — no embeddings, no API key, no network. That
 * is a deliberate first choice rather than a placeholder: a retriever that
 * needs a paid model is a retriever that stops working exactly when the
 * platform is running offline, and one that silently degrades is worse than one
 * that is simply lexical and predictable.
 *
 * Two honesty properties:
 *
 *   - **Every result carries its source and the terms that matched it.** A
 *     caller can always show why a chunk was retrieved.
 *   - **A weak match is dropped, not returned.** Below `minScore` the retriever
 *     answers with nothing. An agent citing a barely-relevant paragraph reads
 *     as authority it has not earned.
 */

import { knowledgeCorpus } from "./corpus";
import type { KnowledgeChunk, RetrievedChunk, RetrieveOptions } from "./types";

/** Standard BM25 constants. */
const K1 = 1.5;
const B = 0.75;

/**
 * Minimum score to be returned at all. Tuned so a query with no real subject
 * overlap yields nothing rather than the least-bad paragraph in the corpus.
 */
export const DEFAULT_MIN_SCORE = 2;

export const DEFAULT_LIMIT = 5;

/** Boost for an exact identifier hit (CWE / OWASP code / MITRE technique id). */
const EXACT_REF_BOOST = 6;

/**
 * Words carrying no subject matter, dropped from both the index and the query.
 * Without this a query scores against "the" and "in", which is how a retriever
 * ends up returning its least-bad paragraph for a question it knows nothing
 * about — precisely the behavior this module must not have.
 */
const STOPWORDS = new Set([
  // English
  "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "can", "for",
  "from", "has", "have", "he", "her", "his", "in", "into", "is", "it", "its",
  "may", "no", "not", "of", "on", "or", "she", "that", "the", "their", "them",
  "then", "there", "these", "they", "this", "to", "was", "were", "when",
  "which", "will", "with", "you", "your",
  // Arabic
  "من", "في", "على", "عن", "إلى", "الى", "هذا", "هذه", "ذلك", "التي", "الذي",
  "مع", "أو", "او", "ثم", "كما", "بين", "عند", "قد", "لا", "ما", "هو", "هي",
  "كان", "يكون", "حتى", "بعد", "قبل", "كل", "أي", "اي", "به", "بها", "لها", "له",
]);

/**
 * Tokenizer. Unicode letters and digits, so Arabic text tokenizes the same way
 * English does; `-`, `+` and `:` survive inside a token so "cwe-89", "a03:2021"
 * and "c++" stay single terms rather than being shredded into noise.
 */
export function tokenize(text: string): string[] {
  return (text || "")
    .toLowerCase()
    .split(/[^\p{L}\p{N}+:_-]+/u)
    .map((t) => t.replace(/^[-:]+|[-:]+$/g, ""))
    .filter((t) => t.length >= 2 && !STOPWORDS.has(t));
}

interface IndexedDoc {
  chunk: KnowledgeChunk;
  termFreq: Map<string, number>;
  length: number;
}

interface Index {
  docs: IndexedDoc[];
  /** Document frequency per term. */
  docFreq: Map<string, number>;
  avgLength: number;
}

let cachedIndex: Index | null = null;

function buildIndex(): Index {
  const docs: IndexedDoc[] = [];
  const docFreq = new Map<string, number>();
  let total = 0;

  for (const chunk of knowledgeCorpus()) {
    // The citation text is indexed alongside the body so a query naming the
    // framework entry ("A03 injection") finds it.
    const tokens = tokenize(`${chunk.text} ${chunk.source.ref} ${chunk.source.title} ${chunk.section}`);
    const termFreq = new Map<string, number>();
    for (const t of tokens) termFreq.set(t, (termFreq.get(t) ?? 0) + 1);
    for (const t of termFreq.keys()) docFreq.set(t, (docFreq.get(t) ?? 0) + 1);
    docs.push({ chunk, termFreq, length: tokens.length });
    total += tokens.length;
  }

  return { docs, docFreq, avgLength: docs.length ? total / docs.length : 0 };
}

function index(): Index {
  if (!cachedIndex) cachedIndex = buildIndex();
  return cachedIndex;
}

/** Test helper: rebuild the index on next use. */
export function resetIndex(): void {
  cachedIndex = null;
}

function idf(term: string, idx: Index): number {
  const df = idx.docFreq.get(term) ?? 0;
  if (df === 0) return 0;
  return Math.log(1 + (idx.docs.length - df + 0.5) / (df + 0.5));
}

/**
 * Retrieve chunks for a free-text query. Results are ordered by score and every
 * one of them carries its source, its citation and the terms that matched.
 */
export function retrieve(query: string, opts: RetrieveOptions = {}): RetrievedChunk[] {
  const idx = index();
  const limit = Math.max(1, Math.min(opts.limit ?? DEFAULT_LIMIT, 50));
  const minScore = opts.minScore ?? DEFAULT_MIN_SCORE;
  const wantedCwe = (opts.cwe ?? []).map((c) => c.trim().toUpperCase()).filter(Boolean);

  const terms = [...new Set(tokenize(query))];
  if (!terms.length && !wantedCwe.length) return [];

  const results: RetrievedChunk[] = [];
  for (const doc of idx.docs) {
    if (opts.kinds?.length && !opts.kinds.includes(doc.chunk.source.kind)) continue;

    let score = 0;
    let exactHit = false;
    const matchedTerms: string[] = [];

    for (const term of terms) {
      const f = doc.termFreq.get(term);
      if (!f) continue;
      const denom = f + K1 * (1 - B + (B * doc.length) / (idx.avgLength || 1));
      score += idf(term, idx) * ((f * (K1 + 1)) / denom);
      matchedTerms.push(term);
    }

    // Exact identifier hits are a lookup, not a similarity judgement, so they
    // are scored separately and reported as their own matched term.
    const chunkCwe = doc.chunk.cwe.map((c) => c.toUpperCase());
    for (const id of wantedCwe) {
      if (chunkCwe.includes(id)) {
        score += EXACT_REF_BOOST;
        exactHit = true;
        matchedTerms.push(id);
      }
    }
    for (const term of terms) {
      const upper = term.toUpperCase();
      if (chunkCwe.includes(upper) || doc.chunk.source.ref.toUpperCase() === upper) {
        score += EXACT_REF_BOOST;
        exactHit = true;
        if (!matchedTerms.includes(term)) matchedTerms.push(term);
      }
    }

    // Coverage rule: for a query that actually says something (three content
    // terms or more), overlapping on a single common word is a coincidence, not
    // a match. An exact identifier hit is exempt — that is a lookup.
    const lexicalMatches = matchedTerms.filter((t) => terms.includes(t)).length;
    const thin = terms.length >= 3 && lexicalMatches < 2 && !exactHit;
    if (score >= minScore && !thin) {
      results.push({ chunk: doc.chunk, score: Number(score.toFixed(4)), matchedTerms });
    }
  }

  return results
    .sort((a, b) => b.score - a.score || a.chunk.id.localeCompare(b.chunk.id))
    .slice(0, limit);
}

/**
 * Retrieval for one finding: its title and CWE ids drive the query, and CWE
 * matches are exact rather than lexical.
 */
export function retrieveForFinding(
  input: { title: string; cwe?: string[]; description?: string },
  opts: RetrieveOptions = {},
): RetrievedChunk[] {
  const cwe = (input.cwe ?? []).map((c) => c.split(":")[0].trim()).filter(Boolean);
  return retrieve(`${input.title} ${input.description ?? ""}`, { ...opts, cwe });
}

/** The distinct citations behind a result set, in the order retrieved. */
export function citationsFor(chunks: RetrievedChunk[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const { chunk } of chunks) {
    if (seen.has(chunk.citation)) continue;
    seen.add(chunk.citation);
    out.push(chunk.citation);
  }
  return out;
}

/**
 * Render chunks for a model prompt. Each block is prefixed with its citation
 * and labelled as reference material, so text that reaches the model can never
 * be mistaken for an observation of the target.
 */
export function formatForPrompt(chunks: RetrievedChunk[]): string {
  if (!chunks.length) return "No reference material matched this finding.";
  return chunks
    .map(({ chunk }) => `[REFERENCE — ${chunk.citation}, from ${chunk.source.origin}]\n${chunk.text}`)
    .join("\n\n");
}
