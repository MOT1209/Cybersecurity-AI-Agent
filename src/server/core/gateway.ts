/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Security gateway (authorization/scope enforcement) + error recovery engine.
 * Extracted from server.ts (Phase 0). Behavior is unchanged; these functions
 * are the mandatory pre-flight for any real tool execution added in Phase 1.
 */

import {
  projectsStore,
  circuitBreakers,
  errorRecoveryEventsStore,
  addAuditLog,
} from "./store";
import { extractHost, matchesAnyScope, isPrivateOrLabHost } from "./scope";
import { getToolDescriptor } from "../tools/registry";
import { policyFor, isCriticalToolEnabled } from "../security/policy";
import type { RiskLevel } from "../tools/types";

export interface GatewayDecision {
  isAllowed: boolean;
  reason: string;
  riskLevel: RiskLevel;
  humanApprovalRequired: boolean;
  scopeValidation: "IN_SCOPE" | "OUT_OF_SCOPE";
  /** Ordered record of every check the request passed or failed. */
  checks: GatewayCheck[];
  sandboxRequired: boolean;
}

export interface GatewayCheck {
  name: string;
  passed: boolean;
  detail: string;
}

/**
 * Validate that a target/tool combination is within the authorized engagement
 * scope for a project. Denies explicit out-of-scope targets, then requires the
 * target to be in-scope (or a lab/local host), and flags high-risk tools for
 * human approval.
 */
export function validateSecurityGateway(
  target: string,
  toolName: string,
  projectId: string = "proj_alpha_lab",
): GatewayDecision {
  const project = projectsStore.find((p) => p.id === projectId) || projectsStore[0];
  const host = extractHost(target);
  const checks: GatewayCheck[] = [];

  // Risk comes from the tool registry, not from a hardcoded name list and not
  // from anything the caller (or a model) can influence. An unregistered tool
  // is treated as CRITICAL so the most restrictive policy applies.
  const descriptor = getToolDescriptor(toolName.toLowerCase());
  const riskLevel: RiskLevel = descriptor?.riskLevel ?? "CRITICAL";
  const policy = policyFor(riskLevel);
  const sandboxRequired = descriptor?.sandboxRequired ?? true;

  const deny = (
    name: string,
    detail: string,
    reason: string,
    scopeValidation: GatewayDecision["scopeValidation"],
  ): GatewayDecision => {
    checks.push({ name, passed: false, detail });
    addAuditLog("SecurityGateway", `EXECUTE_${toolName.toUpperCase()}`, target, "DENIED", detail);
    return {
      isAllowed: false,
      reason,
      riskLevel,
      humanApprovalRequired: false,
      scopeValidation,
      checks,
      sandboxRequired,
    };
  };

  // 1a. Filesystem-scoped tools do not have a network target. Host allow/deny
  //     lists are meaningless for them; containment is enforced separately by
  //     the workspace resolver before the run is built.
  if (descriptor?.targetKind === "filesystem") {
    checks.push({
      name: "target-kind",
      passed: true,
      detail: "Filesystem-scoped tool: containment is enforced by the workspace resolver.",
    });
    const allowed = (project.allowedTools ?? []).map((t) => t.toLowerCase());
    if (allowed.length && !allowed.includes(toolName.toLowerCase())) {
      return deny(
        "project-tool-permission",
        `Tool "${toolName}" is not permitted for project ${project.id}`,
        `SECURITY GATEWAY ENFORCEMENT: Tool "${toolName}" is not in the allowed tool list for project "${project.id}".`,
        "IN_SCOPE",
      );
    }
    checks.push({ name: "project-tool-permission", passed: true, detail: `Tool "${toolName}" is permitted for this project.` });
    const fsPolicy = policyFor(riskLevel);
    if (fsPolicy.disabledByDefault && !isCriticalToolEnabled(toolName)) {
      return deny(
        "risk-policy",
        `${riskLevel}-risk tool "${toolName}" is disabled by default`,
        `SECURITY GATEWAY ENFORCEMENT: Tool "${toolName}" is classified ${riskLevel} and is disabled by default.`,
        "IN_SCOPE",
      );
    }
    checks.push({ name: "risk-policy", passed: true, detail: `Risk ${riskLevel} permitted under the active policy.` });
    checks.push({
      name: "approval-requirement",
      passed: true,
      detail: fsPolicy.requiresApproval ? "Explicit human approval is required." : "No approval required at this risk level.",
    });
    addAuditLog("SecurityGateway", `EXECUTE_${toolName.toUpperCase()}`, target, "ALLOWED", `Filesystem-scoped tool permitted (risk=${riskLevel}).`);
    return {
      isAllowed: true,
      reason: `Filesystem-scoped tool "${toolName}" permitted; workspace containment applies.`,
      riskLevel,
      humanApprovalRequired: fsPolicy.requiresApproval,
      scopeValidation: "IN_SCOPE",
      checks,
      sandboxRequired,
    };
  }

  // 1. Explicit deny-list first: a denied host is rejected even when it would
  //    otherwise qualify as a private/lab address.
  if (matchesAnyScope(host, project.outOfScope)) {
    return deny(
      "target-denylist",
      "Target matches explicit out-of-scope restriction",
      `SECURITY GATEWAY REJECTED: Target "${target}" is explicitly in the OUT-OF-SCOPE list for this project engagement.`,
      "OUT_OF_SCOPE",
    );
  }
  checks.push({ name: "target-denylist", passed: true, detail: "Target is not on the project deny-list." });

  // 2. Allow-list: exact allowlist/targetIps match, or a private/lab host.
  //    Substring tricks like "192.168.1.50.attacker.com" do not pass.
  const isInScope =
    matchesAnyScope(host, project.inScope) ||
    matchesAnyScope(host, project.targetIps) ||
    isPrivateOrLabHost(host);
  if (!isInScope) {
    return deny(
      "target-allowlist",
      "Unauthorized external target outside designated engagement scope",
      `SECURITY GATEWAY ENFORCEMENT: Target "${target}" is NOT registered in the authorized target allowlist. Engagement scope strictly enforces lab/authorized hosts.`,
      "OUT_OF_SCOPE",
    );
  }
  checks.push({ name: "target-allowlist", passed: true, detail: `Host "${host}" is inside the authorized scope.` });

  // 3. Project tool permission. Previously declared but never enforced.
  const allowedTools = (project.allowedTools ?? []).map((t) => t.toLowerCase());
  if (allowedTools.length && !allowedTools.includes(toolName.toLowerCase())) {
    return deny(
      "project-tool-permission",
      `Tool "${toolName}" is not permitted for project ${project.id}`,
      `SECURITY GATEWAY ENFORCEMENT: Tool "${toolName}" is not in the allowed tool list for project "${project.id}".`,
      "IN_SCOPE",
    );
  }
  checks.push({ name: "project-tool-permission", passed: true, detail: `Tool "${toolName}" is permitted for this project.` });

  // 4. Risk policy. CRITICAL is disabled unless explicitly enabled, and then
  //    only against a lab/private target.
  if (policy.disabledByDefault && !isCriticalToolEnabled(toolName)) {
    return deny(
      "risk-policy",
      `${riskLevel}-risk tool "${toolName}" is disabled by default`,
      `SECURITY GATEWAY ENFORCEMENT: Tool "${toolName}" is classified ${riskLevel} and is disabled by default. Enable it explicitly via ENABLE_CRITICAL_TOOLS for controlled lab use.`,
      "IN_SCOPE",
    );
  }
  if (policy.labOnly && !isPrivateOrLabHost(host)) {
    return deny(
      "risk-policy-lab-only",
      `${riskLevel}-risk tool "${toolName}" may only run against a lab/private target`,
      `SECURITY GATEWAY ENFORCEMENT: Tool "${toolName}" is ${riskLevel} risk and is restricted to lab/private targets.`,
      "IN_SCOPE",
    );
  }
  checks.push({ name: "risk-policy", passed: true, detail: `Risk ${riskLevel} permitted under the active policy.` });

  const requiresApproval = policy.requiresApproval || project.policy?.requireApprovalForHighRisk === true && riskLevel === "HIGH";
  checks.push({
    name: "approval-requirement",
    passed: true,
    detail: requiresApproval ? "Explicit human approval is required." : "No approval required at this risk level.",
  });

  addAuditLog(
    "SecurityGateway",
    `EXECUTE_${toolName.toUpperCase()}`,
    target,
    "ALLOWED",
    `Security policies satisfied (risk=${riskLevel}, approval=${requiresApproval}). Sandbox execution granted for ${toolName}.`,
  );
  return {
    isAllowed: true,
    reason: `Target in authorized scope. Sandbox permissions verified for ${toolName}.`,
    riskLevel,
    humanApprovalRequired: requiresApproval,
    scopeValidation: "IN_SCOPE",
    checks,
    sandboxRequired,
  };
}

/**
 * Classify a tool failure, advance the tool's circuit breaker, record a
 * recovery event, and return the diagnosis. Deterministic — used both live and
 * for the recovery simulation route.
 */
export function diagnoseAndRecoverError(params: {
  toolName: string;
  target: string;
  rawError?: string;
  agentId?: string;
  scenarioPreset?: string;
}) {
  const toolName = (params.toolName || "tool").toLowerCase();
  const target = params.target || "192.168.1.50";
  let rawError = params.rawError || "";
  let classification = "TRANSIENT_TIMEOUT";
  let strategy = "EXPONENTIAL_BACKOFF";
  let rootCauseAr = "";
  let rootCauseEn = "";
  let proposedFixAr = "";
  let proposedFixEn = "";
  let alternativeTool = "";
  let backoffDelayMs = 2000;

  if (params.scenarioPreset === "waf_rate_limit" || rawError.includes("429") || rawError.toLowerCase().includes("rate limit")) {
    classification = "RATE_LIMITED";
    strategy = "THROTTLE_AND_RETRY";
    rawError = rawError || "HTTP 429: Too Many Requests from WAF/Reverse Proxy. Request burst exceeded threshold.";
    rootCauseAr = "تجاوز معدل الطلبات المسموح به وخنق الاتصال من قِبل جدار حماية تطبيقات الويب (WAF Rate Limiting).";
    rootCauseEn = "Target WAF/API Gateway rate-limiting triggered due to request burst.";
    proposedFixAr = "تطبيق إعادة المحاولة الآمنة مع تأخير أسي (Backoff: 2500ms) وتخفيض معدل الطلبات إلى 10 طلبات/ثانية.";
    proposedFixEn = "Execute Safe Retry with exponential backoff (2500ms) and throttle rate limit to 10 req/s.";
    alternativeTool = "stealth_nuclei_throttled";
    backoffDelayMs = 2500;
  } else if (params.scenarioPreset === "nmap_syn_timeout" || rawError.includes("SYN") || rawError.toLowerCase().includes("timed out") || rawError.toLowerCase().includes("silent drop")) {
    classification = "PORT_UNREACHABLE";
    strategy = "PROTOCOL_SWITCH";
    rawError = rawError || "TCP SYN probe dropped by stateful firewall. Host unreachable via half-open packets.";
    rootCauseAr = "جدار الحماية في الهدف يسقط حزم SYN الخفية تلقائياً دون إرجاع RST.";
    rootCauseEn = "Target stateful firewall silently dropping SYN packets without returning RST.";
    proposedFixAr = "التحويل التلقائي من SYN Scan (-sS) إلى فحص TCP Connect الكامل (-sT) مع زيادة مهلة انتظار الحزم.";
    proposedFixEn = "Switch from stealth SYN scan (-sS) to full TCP Connect scan (-sT) with increased timeout.";
    alternativeTool = "nmap -sT (Connect Scan)";
    backoffDelayMs = 1800;
  } else if (params.scenarioPreset === "semgrep_oom" || rawError.includes("OOM") || rawError.toLowerCase().includes("memory") || rawError.toLowerCase().includes("heap")) {
    classification = "SANDBOX_RESOURCE_EXHAUSTED";
    strategy = "PARAM_RESTRUCTURING";
    rawError = rawError || "FATAL: AST Memory limit exceeded (Allocated > 512MB in Sandbox container).";
    rootCauseAr = "محاولة تحليل ملفات ضخمة مدمجة (Minified Bundles) أدت إلى استهلاك ذاكرة الحاوية المعزولة.";
    rootCauseEn = "Parsing oversized minified artifacts caused AST memory consumption to exceed 512MB.";
    proposedFixAr = "استبعاد الملفات المجمعة (*.min.js, *.map) وتجزئة الفحص إلى دفعات كود متتابعة.";
    proposedFixEn = "Exclude minified bundles (*.min.js) and partition SAST rule execution into chunked streams.";
    alternativeTool = "semgrep --exclude='*.min.js' --max-target-bytes=5000000";
    backoffDelayMs = 1200;
  } else if (params.scenarioPreset === "zap_proxy_econnrefused" || rawError.includes("ECONNREFUSED") || rawError.toLowerCase().includes("refused") || rawError.toLowerCase().includes("socket")) {
    classification = "TRANSIENT_TIMEOUT";
    strategy = "FALLBACK_TOOL";
    rawError = rawError || "Error: connect ECONNREFUSED 127.0.0.1:8080 - ZAP Daemon Proxy connection failed.";
    rootCauseAr = "انقطاع مفاجئ في مقبس الاتصال مع وكيل ZAP المحلي في الحاوية.";
    rootCauseEn = "Local ZAP proxy socket disconnected or daemon failed to accept downstream socket.";
    proposedFixAr = "إعادة تشغيل وكيل ZAP في بيئة الـ Sandbox مع التبديل المؤقت إلى محرك الزحف الخفيف Headless Crawler.";
    proposedFixEn = "Restart sandbox daemon proxy and fallback to lightweight Headless Crawler.";
    alternativeTool = "Katana Web Crawler (Lightweight Fallback)";
    backoffDelayMs = 2000;
  } else if (rawError.includes("403") || rawError.toLowerCase().includes("forbidden") || rawError.toLowerCase().includes("waf blocked")) {
    classification = "WAF_BLOCKED";
    strategy = "FALLBACK_TOOL";
    rawError = rawError || "HTTP 403 Forbidden: ModSecurity WAF rule triggered on payload signature.";
    rootCauseAr = "تم حظر الحزمة بواسطة جدار حماية تطبيقات الويب (WAF Signature Match / ModSecurity).";
    rootCauseEn = "Payload signature triggered target WAF rule (HTTP 403 Forbidden).";
    proposedFixAr = "تبديل بصمة الفحص (User-Agent & Header Obfuscation) وتخفيف حدة الحمولات مع التحويل لأداة بديلة.";
    proposedFixEn = "Obfuscate inspection headers/user-agents and switch to stealth evasive testing.";
    alternativeTool = "Custom Stealth Engine";
    backoffDelayMs = 3000;
  } else {
    classification = "TRANSIENT_TIMEOUT";
    strategy = "EXPONENTIAL_BACKOFF";
    rawError = rawError || "Command timed out after 30 seconds with no response from target socket.";
    rootCauseAr = "تأخر مؤقت في استجابة الهدف أو فقدان عابر للحزم في الشبكة.";
    rootCauseEn = "Transient network packet drop or target socket latency timeout.";
    proposedFixAr = "إعادة المحاولة الآمنة بعد مهلة أسيّة (Safe Exponential Retry) وزيادة حد الـ Timeout إلى 45 ثانية.";
    proposedFixEn = "Execute Safe Exponential Retry and increase timeout ceiling to 45s.";
    backoffDelayMs = 2000;
  }

  const cb = circuitBreakers[toolName] || { consecutiveFailures: 0, lastFailureTime: 0, state: "CLOSED" as const, cooldownPeriodMs: 20000 };
  cb.consecutiveFailures += 1;
  cb.lastFailureTime = Date.now();
  if (cb.consecutiveFailures >= 4) {
    cb.state = "OPEN";
  } else if (cb.consecutiveFailures >= 2) {
    cb.state = "HALF_OPEN";
  } else {
    cb.state = "CLOSED";
  }
  circuitBreakers[toolName] = cb;

  const event = {
    id: `rec_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    timestamp: new Date().toISOString(),
    toolName: toolName,
    agentId: params.agentId || "recon",
    target: target,
    rawError: rawError,
    rootCauseAr: rootCauseAr,
    rootCauseEn: rootCauseEn,
    classification: classification,
    circuitBreakerState: cb.state,
    retryCount: 1,
    maxRetries: 3,
    backoffDelayMs: backoffDelayMs,
    strategy: strategy,
    proposedFixAr: proposedFixAr,
    proposedFixEn: proposedFixEn,
    alternativeTool: alternativeTool,
    // A diagnosis is a PROPOSAL, not an outcome. Nothing has been retried here:
    // this function classifies a failure and recommends a strategy. Reporting
    // "AUTO_RECOVERED" for a retry that never ran was a fabricated result.
    status: cb.state === "OPEN" ? "ESCALATED" : "RECOVERY_PROPOSED",
    recoveryExecuted: false,
    executionLog: [
      `Tool "${toolName}" reported a failure against target "${target}".`,
      `Observed error: ${rawError.substring(0, 120)}`,
      `Diagnostic engine classified it as [${classification}].`,
      `Circuit breaker for "${toolName}" is now [${cb.state}] after ${cb.consecutiveFailures} consecutive failure(s).`,
      `Recommended strategy: [${strategy}] with a ${backoffDelayMs}ms backoff.`,
      alternativeTool
        ? `Suggested alternative: ${alternativeTool}`
        : "No alternative tool suggested.",
      "NOTE: no retry has been executed. Re-issue the tool request to act on this recommendation.",
    ],
  };

  errorRecoveryEventsStore.unshift(event);
  if (errorRecoveryEventsStore.length > 50) errorRecoveryEventsStore.pop();

  addAuditLog(
    "ErrorRecoverySystem",
    `RECOVER_${toolName.toUpperCase()}`,
    target,
    event.status,
    `Error classified as ${classification}. Recommended strategy: ${strategy}. No retry was executed.`,
  );

  return event;
}
