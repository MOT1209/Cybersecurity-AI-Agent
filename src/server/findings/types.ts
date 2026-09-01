/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Canonical finding format (§18).
 *
 * The central rule this type encodes: a scanner result is NOT a vulnerability.
 * Every finding enters at `DETECTED` with confidence 0 and can only reach
 * `CONFIRMED` through the validation stage. `severity` is what the tool
 * claimed; `verificationStatus` is what the platform is willing to stand behind.
 */

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type VerificationStatus =
  | "DETECTED"
  | "ANALYZING"
  | "CONFIRMED"
  | "UNCONFIRMED"
  | "FALSE_POSITIVE";

export interface Evidence {
  /** Where the evidence came from: tool id, or "agent-analysis". */
  source: string;
  /** What was actually observed. Never a claim, never a hypothesis. */
  observation: string;
  /** sha256 of the raw tool output the observation was drawn from. */
  outputHash?: string;
  collectedAt: string;
}

export interface Validation {
  status: VerificationStatus;
  /** 0-100. Stays 0 until evidence justifies more. */
  confidence: number;
  validatedByAgent?: string;
  validatedAt?: string;
  /** Why the validator reached this conclusion. Always populated once run. */
  rationale?: string;
  /** Specific reasons this could be a false positive. */
  falsePositiveIndicators: string[];
  /** What additional evidence would settle it. */
  missingEvidence: string[];
}

export interface Remediation {
  summary: string;
  hardeningSteps: string[];
  codeFix?: string;
  configPatch?: string;
  verificationInstructions?: string;
  /**
   * Citations for the reference material this guidance was written against,
   * e.g. "OWASP A03:2021 — Injection (prevention/ar)". Guidance the platform
   * cannot attribute travels with an empty list rather than an invented source.
   */
  references?: string[];
}

export interface Finding {
  id: string;
  projectId: string;
  taskId?: string;
  traceId?: string;
  target: string;
  /** The specific asset within the target: a URL, a file path, a port. */
  asset: string;
  discoveredByAgent: string;
  toolUsed: string;
  title: string;
  description: string;
  evidence: Evidence[];
  severity: Severity;
  cvssScore?: number;
  cwe: string[];
  owaspCategory?: string;
  impact: string;
  validation: Validation;
  remediation?: Remediation;
  createdAt: string;
  updatedAt: string;
}

/** A finding the platform is willing to present as real. */
export function isConfirmed(f: Finding): boolean {
  return f.validation.status === "CONFIRMED";
}
