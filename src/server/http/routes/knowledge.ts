/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Knowledge base (§24) and findings (§18) routes. Cited retrieval returns its
 * sources; findings carry their real verification status — a scanner flush
 * alone is DETECTED, never CONFIRMED by assumption.
 */

import type { Express, Response } from "express";
import { validateStringField } from "../../core/index";
import { retrieve as retrieveKnowledge } from "../../knowledge";
import { listFindings, getFinding } from "../../findings/engine";

export function registerKnowledgeRoutes(app: Express) {
  // --- Knowledge base (§24) ---

  /**
   * Cited retrieval over the local security corpus. Every hit carries its
   * source, its citation and the terms that matched; a query with no real
   * overlap returns an empty list rather than the least-bad paragraph.
   */
  app.get("/api/knowledge/search", (req, res: Response) => {
    const q = typeof req.query.q === "string" ? req.query.q : "";
    const check = validateStringField(q, "q", 500, true);
    if (!check.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: check.error });
    }
    const limit = Math.max(1, Math.min(Number(req.query.limit) || 5, 20));
    const hits = retrieveKnowledge(q, { limit });
    res.json({
      query: q,
      count: hits.length,
      // Said plainly, so an empty result is never read as a failed request.
      note: hits.length
        ? "Every result carries the source it came from."
        : "Nothing in the local corpus matched this query closely enough to cite.",
      results: hits.map((h) => ({
        id: h.chunk.id,
        citation: h.chunk.citation,
        kind: h.chunk.source.kind,
        ref: h.chunk.source.ref,
        title: h.chunk.source.title,
        origin: h.chunk.source.origin,
        section: h.chunk.section,
        language: h.chunk.language,
        text: h.chunk.text,
        cwe: h.chunk.cwe,
        score: h.score,
        matchedTerms: h.matchedTerms,
      })),
    });
  });

  // --- Findings (§18) ---

  /**
   * Findings with their true verification status. A finding is only ever
   * CONFIRMED if the Validation agent said so; scanner output alone stays
   * DETECTED. Filter with ?status=, ?projectId=, ?traceId=, ?minSeverity=.
   * Pagination: ?page=1&perPage=50 (max 200). Returns X-Total-Count and X-Page-Count headers.
   */
  app.get("/api/findings", (req, res: Response) => {
    const q = req.query as Record<string, string | undefined>;
    const page = Math.max(1, Number(q.page) || 1);
    const perPage = Math.max(1, Math.min(Number(q.perPage) || 50, 200));
    const skip = (page - 1) * perPage;

    const findings = listFindings({
      projectId: q.projectId,
      traceId: q.traceId,
      status: q.status as never,
      minSeverity: q.minSeverity as never,
    });

    const total = findings.length;
    const pageCount = Math.max(1, Math.ceil(total / perPage));

    const pagedFindings = findings.slice(skip, skip + perPage);

    // Set pagination headers
    res.setHeader("X-Total-Count", String(total));
    res.setHeader("X-Page-Count", String(pageCount));

    res.json({
      findings: pagedFindings,
      counts: {
        total,
        confirmed: pagedFindings.filter((f) => f.validation.status === "CONFIRMED").length,
        detected: pagedFindings.filter((f) => f.validation.status === "DETECTED").length,
        unconfirmed: pagedFindings.filter((f) => f.validation.status === "UNCONFIRMED").length,
      },
      pagination: {
        page,
        perPage,
        total,
        pageCount,
      },
    });
  });

  app.get("/api/findings/:id", (req, res: Response) => {
    const f = getFinding(req.params.id);
    if (!f) return res.status(404).json({ error: "NOT_FOUND", message: "No such finding." });
    res.json(f);
  });
}