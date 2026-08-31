/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Findings engine (§18). Normalizes raw tool detections into the canonical
 * finding format and holds them.
 *
 * Every normalizer here enters findings at `DETECTED` with confidence 0. There
 * is deliberately no path in this module that produces a `CONFIRMED` finding —
 * only the validation stage can move one, so no amount of scanner output can
 * mint a confirmed vulnerability by itself.
 */

import crypto from "crypto";
import { emitEvent } from "../core/events";
import { getDatabase } from "../database/index";
import type { Evidence, Finding, Severity, Validation } from "./types";
import type { NucleiDetection } from "../tools/nuclei";
import type { SemgrepFinding } from "../tools/semgrep";
import type { TrivyFinding } from "../tools/trivy";
import type { NmapPort } from "../tools/nmap";

const findings: Finding[] = [];

const SEVERITY_ORDER: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

export function normalizeSeverity(raw: string): Severity {
  const up = String(raw || "").toUpperCase();
  return (SEVERITY_ORDER as string[]).includes(up) ? (up as Severity) : "INFO";
}

/** A fresh, unvalidated verdict. The only state a detection may start in. */
function pristineValidation(): Validation {
  return {
    status: "DETECTED",
    confidence: 0,
    falsePositiveIndicators: [],
    missingEvidence: ["No validation has been performed yet."],
  };
}

export interface FindingContext {
  projectId: string;
  target: string;
  agentId: string;
  toolId: string;
  traceId?: string;
  taskId?: string;
  /** sha256 of the raw output these detections were parsed from. */
  outputHash?: string;
}

function base(ctx: FindingContext, asset: string): Pick<
  Finding,
  "id" | "projectId" | "taskId" | "traceId" | "target" | "asset" | "discoveredByAgent" | "toolUsed" | "createdAt" | "updatedAt" | "validation"
> {
  const now = new Date().toISOString();
  return {
    id: `find_${crypto.randomUUID()}`,
    projectId: ctx.projectId,
    taskId: ctx.taskId,
    traceId: ctx.traceId,
    target: ctx.target,
    asset,
    discoveredByAgent: ctx.agentId,
    toolUsed: ctx.toolId,
    createdAt: now,
    updatedAt: now,
    validation: pristineValidation(),
  };
}

function evidence(ctx: FindingContext, observation: string): Evidence[] {
  return [
    {
      source: ctx.toolId,
      observation,
      outputHash: ctx.outputHash,
      collectedAt: new Date().toISOString(),
    },
  ];
}

/** nmap open ports → one informational exposure finding per open port. */
export function fromNmapPorts(ports: NmapPort[], ctx: FindingContext): Finding[] {
  return ports
    .filter((p) => p.state === "open")
    .map((p) => ({
      ...base(ctx, `${ctx.target}:${p.port}/${p.protocol}`),
      title: `Open ${p.protocol.toUpperCase()} port ${p.port} (${p.service})`,
      description: `nmap observed port ${p.port}/${p.protocol} in state "open" running "${p.service}".`,
      evidence: evidence(ctx, `${p.port}/${p.protocol} open ${p.service}`),
      severity: normalizeSeverity(p.port === 23 || p.port === 21 ? "MEDIUM" : "INFO"),
      cwe: ["CWE-200"],
      owaspCategory: "A05:2021-Security Misconfiguration",
      impact: "An exposed service widens the attack surface and should be justified or closed.",
    }));
}

/** nuclei detections → findings. Severity is the template's claim, not a verdict. */
export function fromNucleiDetections(detections: NucleiDetection[], ctx: FindingContext): Finding[] {
  return detections.map((d) => ({
    ...base(ctx, d.matchedAt || ctx.target),
    title: d.name,
    description:
      d.description ||
      `nuclei template "${d.templateId}" matched. This is a detection, not a confirmed vulnerability.`,
    evidence: evidence(ctx, `template ${d.templateId} matched at ${d.matchedAt || ctx.target}`),
    severity: normalizeSeverity(d.severity),
    cwe: d.cwe ?? [],
    impact: "If confirmed, this could be exploitable; the detection alone does not establish that.",
  }));
}

/** semgrep results → findings anchored to a file and line. */
export function fromSemgrepFindings(results: SemgrepFinding[], ctx: FindingContext): Finding[] {
  return results.map((f) => ({
    ...base(ctx, `${f.path}:${f.startLine}`),
    title: f.ruleId,
    description: f.message,
    evidence: evidence(ctx, `${f.ruleId} matched ${f.path} lines ${f.startLine}-${f.endLine}`),
    severity: normalizeSeverity(f.severity),
    cwe: f.cwe,
    owaspCategory: f.owasp[0],
    impact: "A static-analysis match indicates a risky pattern; reachability is not established.",
  }));
}

/** trivy results → findings. Secret VALUES are never carried through. */
export function fromTrivyFindings(results: TrivyFinding[], ctx: FindingContext): Finding[] {
  return results.map((f) => ({
    ...base(ctx, f.target || ctx.target),
    title: f.title,
    description:
      f.kind === "vulnerability"
        ? `${f.id} affects ${f.pkgName ?? "a dependency"} ${f.installedVersion ?? ""}`.trim() +
          (f.fixedVersion ? ` (fixed in ${f.fixedVersion})` : "")
        : `${f.kind} "${f.id}" reported in ${f.target || ctx.target}.`,
    evidence: evidence(ctx, `${f.kind} ${f.id} in ${f.target || ctx.target}`),
    severity: normalizeSeverity(f.severity),
    cwe: [],
    impact:
      f.kind === "secret"
        ? "A committed credential must be treated as compromised and rotated."
        : "A vulnerable dependency may be exploitable depending on how it is used.",
  }));
}

/**
 * Persist findings and announce them.
 *
 * The write-through to the configured backend is intentionally not awaited: a
 * slow database must not stall a scan. It is also not swallowed — a failed
 * write is surfaced, because silently losing a finding is exactly the failure
 * mode this platform refuses elsewhere.
 */
export function recordFindings(newFindings: Finding[]): Finding[] {
  for (const f of newFindings) {
    findings.unshift(f);
    emitEvent("FINDING_CREATED", {
      traceId: f.traceId,
      projectId: f.projectId,
      target: f.target,
      toolId: f.toolUsed,
      agentId: f.discoveredByAgent,
      detail: `${f.severity} ${f.title} [${f.validation.status}]`,
    });
  }
  while (findings.length > 500) findings.pop();

  void getDatabase()
    .findings.insertMany(newFindings)
    .catch((err: Error) => {
      console.error(
        `[findings] Failed to persist ${newFindings.length} finding(s): ${err.message}. ` +
          "They remain in memory only and will be lost on restart.",
      );
    });

  return newFindings;
}

export interface FindingQuery {
  projectId?: string;
  traceId?: string;
  status?: Finding["validation"]["status"];
  minSeverity?: Severity;
}

export function listFindings(q: FindingQuery = {}): Finding[] {
  const min = q.minSeverity ? SEVERITY_ORDER.indexOf(q.minSeverity) : -1;
  return findings.filter(
    (f) =>
      (!q.projectId || f.projectId === q.projectId) &&
      (!q.traceId || f.traceId === q.traceId) &&
      (!q.status || f.validation.status === q.status) &&
      (min < 0 || SEVERITY_ORDER.indexOf(f.severity) >= min),
  );
}

export function getFinding(id: string): Finding | undefined {
  return findings.find((f) => f.id === id);
}

/** Apply a validation verdict. The ONLY way a finding changes status. */
export function applyValidation(id: string, validation: Validation): Finding | undefined {
  const f = findings.find((x) => x.id === id);
  if (!f) return undefined;
  f.validation = validation;
  f.updatedAt = new Date().toISOString();
  void getDatabase()
    .findings.updateValidation(id, validation)
    .catch((err: Error) => {
      console.error(`[findings] Failed to persist validation for ${id}: ${err.message}`);
    });

  emitEvent("FINDING_VALIDATED", {
    traceId: f.traceId,
    projectId: f.projectId,
    target: f.target,
    agentId: validation.validatedByAgent,
    detail: `${f.id} → ${validation.status} (confidence ${validation.confidence})`,
  });
  return f;
}

/**
 * Attach remediation guidance to a finding.
 *
 * Kept separate from applyValidation so remediation can never change a
 * finding's verification status — advice must not be able to promote a
 * detection into a confirmed vulnerability.
 */
export function attachRemediation(id: string, remediation: Finding["remediation"]): Finding | undefined {
  const f = findings.find((x) => x.id === id);
  if (!f) return undefined;
  f.remediation = remediation;
  f.updatedAt = new Date().toISOString();
  emitEvent("REMEDIATION_CREATED", {
    traceId: f.traceId,
    projectId: f.projectId,
    target: f.target,
    detail: `${f.id} → remediation attached (status unchanged: ${f.validation.status})`,
  });
  return f;
}

/** Test helper. */
export function resetFindings(): void {
  findings.length = 0;
}
