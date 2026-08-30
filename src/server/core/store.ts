/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * In-memory application state + audit trail. Extracted from server.ts (Phase 0).
 *
 * The exported arrays/objects are the single source of truth and are mutated by
 * reference (unshift/pop) across the app, exactly as before the extraction. A
 * later phase replaces these with a real database (Drizzle/Postgres).
 */

import { createHash } from "crypto";

// In-Memory Project & Scope State
export const projectsStore = [
  {
    id: "proj_alpha_lab",
    name: "Authorized Enterprise Staging Lab",
    targetDomain: "target-corp.lab",
    targetIps: ["192.168.1.50", "192.168.1.51", "10.0.0.12", "127.0.0.1", "localhost"],
    inScope: ["192.168.1.50", "192.168.1.51", "*.target-corp.lab", "http://192.168.1.50:8080/api/v1/*"],
    outOfScope: ["192.168.1.1", "production-billing.target-corp.com", "8.8.8.8"],
    allowedTools: ["nmap", "nuclei", "subfinder", "semgrep", "trivy", "zap", "prowler", "volatility"],
    policy: {
      strictSandbox: true,
      requireApprovalForHighRisk: true,
    },
  },
];

export interface AuditLogEntry {
  id: string;
  traceId: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  status: string;
  details: string;
  ipAddress: string;
  /** sha256 of raw tool output, when applicable — enables report traceability. */
  outputHash?: string;
}

// Audit Trail Logs Store
export const auditLogsStore: AuditLogEntry[] = [];

/**
 * Append an immutable-style audit record (newest first, capped at 200).
 *
 * `rawOutput` is optional and, when provided, is hashed (sha256) rather than
 * stored — so report findings can reference a verifiable output fingerprint
 * without persisting sensitive raw output in the log.
 */
export function addAuditLog(
  actor: string,
  action: string,
  target: string,
  status: string,
  details: string,
  rawOutput?: string,
): AuditLogEntry {
  const log: AuditLogEntry = {
    id: `log_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    traceId: `trace_${Date.now()}`,
    timestamp: new Date().toISOString(),
    actor,
    action,
    target,
    status,
    details,
    ipAddress: "127.0.0.1 (Sandbox)",
  };
  if (typeof rawOutput === "string") {
    log.outputHash = `sha256:${createHash("sha256").update(rawOutput).digest("hex")}`;
  }
  auditLogsStore.unshift(log);
  if (auditLogsStore.length > 200) auditLogsStore.pop();
  return log;
}

// Error Recovery & Circuit Breakers Management
export interface ToolCircuitBreaker {
  consecutiveFailures: number;
  lastFailureTime: number;
  state: "CLOSED" | "HALF_OPEN" | "OPEN";
  cooldownPeriodMs: number;
}

export const circuitBreakers: Record<string, ToolCircuitBreaker> = {
  nmap: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 20000 },
  nuclei: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 30000 },
  semgrep: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 15000 },
  zap: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 30000 },
  trivy: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 20000 },
  prowler: { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED", cooldownPeriodMs: 25000 },
};

export const errorRecoveryEventsStore: any[] = [
  {
    id: "rec_101",
    timestamp: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
    toolName: "nuclei",
    agentId: "web_security",
    target: "192.168.1.50",
    rawError: "HTTP 429: Rate limit exceeded (150 req/s). Target WAF returned 429 Too Many Requests with Retry-After: 3s",
    rootCauseAr: "تجاوز معدل الطلبات المسموح به وخنق الحزم من جدار الحماية (WAF Rate Limiting / 429 Too Many Requests).",
    rootCauseEn: "Target WAF/API Gateway rate-limiting triggered due to excessive request concurrency (150 req/s).",
    classification: "RATE_LIMITED",
    circuitBreakerState: "CLOSED",
    retryCount: 1,
    maxRetries: 3,
    backoffDelayMs: 2500,
    strategy: "THROTTLE_AND_RETRY",
    proposedFixAr: "تقليل معدل الإرسال (Rate Limit) إلى 15 طلب/ثانية وتفعيل الـ Exponential Jitter Backoff مع تأخير 2500ms.",
    proposedFixEn: "Throttle concurrency to 15 req/s and enable exponential jitter backoff with 2500ms delay.",
    alternativeTool: "stealth_nuclei_throttled",
    status: "AUTO_RECOVERED",
    executionLog: [
      "[00:00.100] Nuclei scan initiated with 150 concurrency against target",
      "[00:01.400] Error detected: HTTP 429 Too Many Requests (WAF Throttle)",
      "[00:01.410] Error Recovery Engine activated -> Classified as RATE_LIMITED",
      "[00:01.420] Strategy THROTTLE_AND_RETRY applied with backoff: 2500ms",
      "[00:03.920] Safe Retry executed: Concurrency adjusted to 15 req/s with stealth headers",
      "[00:05.100] Response 200 OK received. Scan completed with zero dropped packets."
    ]
  },
  {
    id: "rec_102",
    timestamp: new Date(Date.now() - 1000 * 60 * 22).toISOString(),
    toolName: "nmap",
    agentId: "recon",
    target: "192.168.1.51",
    rawError: "SYN Stealth scan (-sS) timed out: Host stateful firewall dropped half-open probe packets silently",
    rootCauseAr: "جدار حماية المضيف يقوم بإسقاط حزم SYN الصامتة دون إرجاع RST (Stateful Firewall Silent Drop).",
    rootCauseEn: "Host firewall silently dropping raw SYN packets, preventing TCP half-open handshake.",
    classification: "PORT_UNREACHABLE",
    circuitBreakerState: "CLOSED",
    retryCount: 1,
    maxRetries: 3,
    backoffDelayMs: 1800,
    strategy: "PROTOCOL_SWITCH",
    proposedFixAr: "التحويل التلقائي إلى فحص TCP Connect الكامل (-sT) مع زيادة مهلة الاستجابة وتمرير الـ ACK.",
    proposedFixEn: "Switch protocol to full TCP Connect scan (-sT) with increased host timeout.",
    alternativeTool: "nmap -sT (Full TCP Connect)",
    status: "FALLBACK_SUCCESS",
    executionLog: [
      "[00:00.050] Executing nmap -sS -p 1-1000 192.168.1.51",
      "[00:04.200] Host discovery failed: All SYN packets filtered / silent drop",
      "[00:04.220] Error Recovery Engine: Port Unreachable / SYN Filter detected",
      "[00:04.230] Executing Safe Protocol Fallback: Switching from -sS to -sT",
      "[00:06.100] TCP Connect handshake established on ports 22, 80, 443. Recovered successfully."
    ]
  },
  {
    id: "rec_103",
    timestamp: new Date(Date.now() - 1000 * 60 * 40).toISOString(),
    toolName: "semgrep",
    agentId: "code_security",
    target: "repo/bundle.min.js (25MB)",
    rawError: "FATAL: AST Parser Out of Memory (OOM) allocation exceeded 512MB on minified single-line bundle",
    rootCauseAr: "ملف JavaScript مدمج ومضغوط بحجم 25MB استهلك ذاكرة الـ Sandbox أثناء بناء شجرة الـ AST.",
    rootCauseEn: "Minified 25MB JS artifact caused AST parser memory spike exceeding 512MB sandbox limit.",
    classification: "SANDBOX_RESOURCE_EXHAUSTED",
    circuitBreakerState: "CLOSED",
    retryCount: 1,
    maxRetries: 2,
    backoffDelayMs: 1200,
    strategy: "PARAM_RESTRUCTURING",
    proposedFixAr: "استبعاد الملفات المجمعة minified تلقائياً وتفعيل الفحص على الملفات المصدرية فقط (--exclude=*.min.js).",
    proposedFixEn: "Automatically exclude minified vendor bundles and scan source files via chunked AST.",
    alternativeTool: "semgrep --exclude='*.min.js'",
    status: "AUTO_RECOVERED",
    executionLog: [
      "[00:00.100] Semgrep SAST scan started on workspace",
      "[00:02.800] OOM Triggered on bundle.min.js (Allocation > 512MB)",
      "[00:02.810] Error Recovery: SANDBOX_RESOURCE_EXHAUSTED classified",
      "[00:02.820] Applying parameter patch: Excluded *.min.js and vendor folders",
      "[00:04.100] Scan completed cleanly on 48 source files with 0 memory errors."
    ]
  }
];
