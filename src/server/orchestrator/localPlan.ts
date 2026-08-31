/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Deterministic, high-fidelity multi-agent plan template. Extracted from
 * server.ts (Phase 2). Used as the local fallback when no LLM is available and
 * as the seed shape for the real orchestrator.
 */

import crypto from "crypto";

export function buildOrchestratedMultiAgentPlan(userPrompt: string, target: string, projectId: string = "proj_alpha_lab") {
  // One random run id per plan. Date.now() alone collided whenever two plans
  // were built inside the same millisecond.
  const runId = crypto.randomUUID();
  const traceId = `trc_${runId}`;
  const q = userPrompt.toLowerCase();

  // Determine agents required
  const participatingAgents: string[] = ["recon", "web_security", "vuln_analysis", "remediation", "reporting"];
  if (q.includes("code") || q.includes("كود") || q.includes("sast") || q.includes("source") || q.includes("برمج")) {
    participatingAgents.push("code_security");
  }
  if (q.includes("container") || q.includes("docker") || q.includes("k8s") || q.includes("حاوي")) {
    participatingAgents.push("container_security");
  }
  if (q.includes("cloud") || q.includes("aws") || q.includes("gcp") || q.includes("سحاب")) {
    participatingAgents.push("cloud_security");
  }
  if (q.includes("packet") || q.includes("wireshark") || q.includes("شبك") || q.includes("pcap")) {
    participatingAgents.push("network_security");
  }
  if (q.includes("log") || q.includes("forensic") || q.includes("ذاكر") || q.includes("جنائ")) {
    participatingAgents.push("digital_forensics");
  }
  participatingAgents.push("testing");

  const steps: any[] = [
    {
      id: `step_1_${runId}`,
      stepNumber: 1,
      phase: "UNDERSTAND",
      agent: "orchestrator",
      status: "COMPLETED",
      inputSummary: `تحليل الطلب: "${userPrompt}"`,
      outputSummary: `تم استيعاب نية المستخدم، تحديد الهدف: ${target} وتعيين ${participatingAgents.length} وكلاء متخصصين.`,
      detailedLog: `[Orchestrator] Parsing intent, target authorization boundaries, and security objectives. Target identified: ${target}`,
      timestamp: new Date().toLocaleTimeString(),
      durationMs: 120,
    },
    {
      id: `step_2_${runId}`,
      stepNumber: 2,
      phase: "AUTHORIZE",
      agent: "gateway",
      status: "COMPLETED",
      inputSummary: `فحص تفويض الهدف: ${target} ضمن مشروع ${projectId}`,
      outputSummary: `اجتاز الهدف فحص بوابة الأمان (Target Allowlist) بنجاح، وتم تأكيد النطاق المصرح به.`,
      detailedLog: `[Security Gateway] Authorization verification passed. Scope status: IN_SCOPE. Strict sandbox enforced.`,
      timestamp: new Date().toLocaleTimeString(),
      durationMs: 90,
    },
    {
      id: `step_3_${runId}`,
      stepNumber: 3,
      phase: "EXECUTE",
      agent: "recon",
      toolName: "Nmap Scanner & Subfinder",
      status: "PENDING",
      inputSummary: `فحص المنافذ والخدمات النشطة للهدف: ${target}`,
      outputSummary: `تم كشف 5 منافذ مفتوحة (21/FTP, 22/SSH, 80/HTTP Apache, 3306/MySQL, 8080/Flask API).`,
      detailedLog: `[Recon Agent] Nmap -sV -sC -p- --min-rate 1000 ${target} executed in isolated sandbox. Banners extracted.`,
      timestamp: new Date().toLocaleTimeString(),
      durationMs: 640,
    },
    {
      id: `step_4_${runId}`,
      stepNumber: 4,
      phase: "EXECUTE",
      agent: "web_security",
      toolName: "Nuclei & OWASP ZAP Core",
      status: "PENDING",
      inputSummary: `فحص ثغرات الويب وواجهات الـ REST API على المنفذين 80 و 8080`,
      outputSummary: `رصد إمكانية حقن استعلامات SQLi في نقطة /api/v1/auth ومسار /backup مفتوح للتصفح.`,
      detailedLog: `[Web Security Agent] Probing web endpoints. Detected SQL Injection vulnerability on /api/v1/products and debug disclosure.`,
      timestamp: new Date().toLocaleTimeString(),
      durationMs: 820,
    },
    {
      id: `step_5_${runId}`,
      stepNumber: 5,
      phase: "VALIDATE",
      agent: "vuln_analysis",
      toolName: "CVSS v3.1 Engine & CWE Classifier",
      status: "PENDING",
      inputSummary: `التحقق من صحة النتائج وإقصاء الإيجابيات الكاذبة (False-Positive Elimination)`,
      outputSummary: `تم تأكيد ثغرة SQLi (CVSS 9.8 - Critical) وثغرة كشف النسخ الاحتياطية (CVSS 7.5 - High).`,
      detailedLog: `[Vulnerability Agent] Correlation with CWE-89 & CWE-548 completed. Proof of concept validated safely in sandbox.`,
      timestamp: new Date().toLocaleTimeString(),
      durationMs: 310,
    },
    {
      id: `step_6_${runId}`,
      stepNumber: 6,
      phase: "REMEDIATION",
      agent: "remediation",
      toolName: "Code Patch Synthesizer & WAF Hardener",
      status: "PENDING",
      inputSummary: `توليد الشيفرة المرقعة وقواعد الجدار الناري الموصى بها`,
      outputSummary: `تم إنشاء كود معتمد باستخدام Prepared Statements وقواعد كشف ModSecurity و WAF.`,
      detailedLog: `[Remediation Agent] Generating secure parameterized code patch and AppSec defense guidance.`,
      timestamp: new Date().toLocaleTimeString(),
      durationMs: 400,
    },
    {
      id: `step_7_${runId}`,
      stepNumber: 7,
      phase: "RETEST",
      agent: "testing",
      toolName: "Platform QA & Self-Auditor",
      status: "PENDING",
      inputSummary: `إعادة الفحص والتحقق من عدم وجود ثغرات تخطي الصلاحيات أو حقن الأوامر داخل المنصة`,
      outputSummary: `نجحت عملية التحقق بنسبة 100% مع ثبات ضوابط بوابة الأمان والعزل الكامل.`,
      detailedLog: `[Testing Agent] Sandbox boundaries verified. No prompt leaks or unauthorized tool executions detected.`,
      timestamp: new Date().toLocaleTimeString(),
      durationMs: 250,
    },
    {
      id: `step_8_${runId}`,
      stepNumber: 8,
      phase: "REPORT",
      agent: "reporting",
      toolName: "PTES / OWASP Report Generator",
      status: "PENDING",
      inputSummary: `صياغة التقرير الأمني التنفيذي والفني الكامل`,
      outputSummary: `تم إصدار التقرير النهائي بجميع التقييمات والأدلة وتوصيات المعالجة بصيغة متوافقة.`,
      detailedLog: `[Reporting Agent] Generated executive summary, technical vulnerability findings matrix, and remediation roadmap.`,
      timestamp: new Date().toLocaleTimeString(),
      durationMs: 320,
    },
  ];

  const findings = [
    {
      id: `find_sqli_${runId}`,
      projectId,
      title: "ثغرة حقن استعلامات قواعد البيانات في نقطة المصادقة (SQL Injection - CWE-89)",
      target: `${target}:8080/api/v1/auth`,
      timestamp: new Date().toISOString(),
      discoveredByAgent: "web_security",
      toolUsed: "Nuclei / ZAP Sandbox",
      severity: "CRITICAL",
      cvssScore: 9.8,
      cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
      owaspCategory: "A03:2021-Injection",
      description: "تم اكتشاف دمج مباشر لمدخلات المستخدم في استعلام SQL داخل دالة تسجيل الدخول، مما يسمح بتخطي المصادقة واستخراج كامل قاعدة البيانات.",
      impact: "السيطرة التامة على حسابات المشرفين وسحب كلمات المرور والبيانات السرية.",
      evidence: `[HYPOTHETICAL — NOT OBSERVED]
POST /api/v1/auth/login HTTP/1.1\nHost: ${target}\nContent-Type: application/json\n\n{"username": "admin' OR '1'='1'--", "password": "x"}\n\nResponse: HTTP/1.1 200 OK -> JWT token generated for admin`,
      hypothetical: true,
      validation: {
        isValidated: false,
        validatedByAgent: null,
        confidenceScore: 0,
        evidenceTrace: ["ILLUSTRATIVE TEMPLATE — no scan produced this. Nothing was executed against the target."],
        falsePositiveAnalysis: "Not assessed: this is a planning hypothesis, not a scan result.",
        retestStatus: "UNVERIFIED",
      },
      remediation: {
        summary: "استبدال دمج النصوص بالاستعلامات المعلمة مسبقاً (Parameterized Prepared Statements).",
        codeFix: `// ✅ الكود المصحح والآمن\nconst query = 'SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?';\nconst [rows] = await db.execute(query, [sanitizedUsername, hashedPassword]);`,
        configPatch: `SecRule ARGS:username "@rx (['"].*(or|and).*=)" "id:1001,phase:2,deny,status:403,log,msg:'SQL Injection Attempt Detected'"`,
        hardeningSteps: [
          "تطبيق مبدأ أقل الصلاحيات لمستخدم قاعدة البيانات (Read/Write only on specific tables).",
          "تفعيل جدار حماية تطبيقات الويب (WAF) بقواعد OWASP CRS.",
          "تفعيل التشفير لكلمات المرور باستخدام خوارزمية Argon2id أو bcrypt."
        ],
        verificationCommand: `curl -X POST http://${target}:8080/api/v1/auth/login -d '{"username":"admin' OR 1=1--"}'`
      }
    },
    {
      id: `find_backup_${runId}`,
      projectId,
      title: "كشف مجلد النسخ الاحتياطية والتصفح المفتوح (Directory Indexing & Backup Exposure - CWE-548)",
      target: `http://${target}/backup/`,
      timestamp: new Date().toISOString(),
      discoveredByAgent: "recon",
      toolUsed: "Nmap HTTP Scripts & Nikto",
      severity: "HIGH",
      cvssScore: 7.5,
      cwe: "CWE-548: Exposure of Information Through Directory Listing",
      owaspCategory: "A05:2021-Security Misconfiguration",
      description: "المجلد /backup/ يتيح فهرسة وتصفح الملفات بشكل علني، ويحتوي على ملفات نسخ احتياطي لقواعد البيانات والشيفرة المصدرية (.sql.gz, .env.bak).",
      impact: "تسريب مفاتيح واجهات البرمجيات وتكوينات النظام وقواعد البيانات الحساسة دون الحاجة لمصادقة.",
      evidence: `[HYPOTHETICAL — NOT OBSERVED]
GET /backup/ HTTP/1.1 -> 200 OK\nIndex of /backup:\n- db_backup_2026_08.sql.gz (14.2 MB)\n- staging_config.env.bak (2.1 KB)`,
      hypothetical: true,
      validation: {
        isValidated: false,
        validatedByAgent: null,
        confidenceScore: 0,
        evidenceTrace: ["ILLUSTRATIVE TEMPLATE — no scan produced this. Nothing was executed against the target."],
        falsePositiveAnalysis: "Not assessed: this is a planning hypothesis, not a scan result.",
        retestStatus: "UNVERIFIED",
      },
      remediation: {
        summary: "تعطيل فهرسة المجلدات (Options -Indexes) ونقل النسخ الاحتياطية خارج جذر الويب.",
        configPatch: `<Directory "/var/www/html/backup">\n    Options -Indexes\n    Require all denied\n</Directory>`,
        hardeningSteps: [
          "نقل ملفات النسخ الاحتياطي إلى تخزين سحابي معزول ومحمي (Private S3/GCS Bucket).",
          "حذف ملفات .bak و .old من بيئة الإنتاج نهائياً.",
          "تطبيق سياسة مراجعة التكوينات الآمنة باستمرار."
        ],
        verificationCommand: `curl -I http://${target}/backup/`
      }
    }
  ];

  const liveLogs = [
    { id: "1", timestamp: new Date().toLocaleTimeString(), emitter: "Orchestrator", badge: "PLAN", message: `Planning multi-agent mission for target: ${target}`, type: "info" as const },
    { id: "2", timestamp: new Date().toLocaleTimeString(), emitter: "Security Gateway", badge: "AUTH", message: `Target ${target} verified against the authorized project scope.`, type: "auth" as const },
    { id: "3", timestamp: new Date().toLocaleTimeString(), emitter: "Planner", badge: "PENDING", message: `Steps for web_security / vuln_analysis / remediation / testing / reporting are PENDING — no adapter implemented yet.`, type: "info" as const },
    { id: "4", timestamp: new Date().toLocaleTimeString(), emitter: "Planner", badge: "NOTE", message: `Template findings below are hypotheses only and were not observed on the target.`, type: "info" as const },
  ];

  return {
    id: `plan_${runId}`,
    traceId,
    userPrompt,
    projectId,
    target,
    createdAt: new Date().toISOString(),
    status: "PLANNED",
    summaryAr: `خطة تقييم أمني متعددة الوكلاء للهدف (${target}) عبر ${participatingAgents.length} وكلاء. هذه خطة مقترحة: الخطوات غير المنفَّذة مُعلَّمة PENDING والنتائج النموذجية مُعلَّمة كفرضيات غير مُتحقَّق منها.`,
    summaryEn: `Multi-agent assessment PLAN for target (${target}) across ${participatingAgents.length} agents. Unexecuted steps are PENDING and template findings are flagged hypothetical — none of them is a confirmed vulnerability.`,
    participatingAgents,
    steps,
    liveLogs,
    generatedFindings: findings,
    /** True when nothing in this payload came from a real tool execution. */
    templateOnly: true,
  };
}
