/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * The fifty-agent catalog (P2). This manifest is the single source of truth for
 * what the platform ships. It is validated at load by `validateCatalog`, so a
 * duplicate id, a broken ordinal or a reference to a tool the registry does not
 * know fails the build instead of surfacing as drift later.
 *
 * Honesty contract: an entry here is a *catalog claim*. Whether it is
 * executable is decided by the runtime service in `index.ts`, which requires
 * both a registered agent AND a real adapter for every tool the entry lists.
 * CAPABILITY does not imply EXECUTABLE.
 */

import type { AgentManifestEntry } from "./types";

const K = (...tools: string[]) => tools;

/**
 * Static catalog claims for all fifty agents. For the seven runtime agents
 * (recon, web_security, code_security, validation, remediation, reporting,
 * testing) the manifest is a placeholder that the service OVERLAYS with the
 * live descriptor — name, capabilities, tools and risk always come from the
 * registered descriptor, never from a hand-entered copy, so the two cannot
 * drift. The remaining forty-three are catalog-only ambitions and are labeled
 * exactly that on the wire.
 */
export const AGENT_MANIFEST: AgentManifestEntry[] = [
  // ── Recon ────────────────────────────────────────────────────────────────
  {
    id: "recon", ordinal: 1, domain: "recon",
    nameEn: "Reconnaissance Agent", nameAr: "وكيل الاستطلاع الأولي",
    descriptionEn: "Primary passive/active reconnaissance across a target scope: surface mapping, host enumeration and an initial exposure picture.",
    descriptionAr: "الاستطلاع الأولي للنطاق المستهدف: رسم السطح، تعداد المضيفين، وصورة أولية للتعرض.",
    capabilities: ["address-scan", "port-probe", "dns-discovery"], skills: ["nmap", "subfinder"],
    requiredTools: K("nmap", "subfinder"), permissions: ["network:scan"], riskLevel: "HIGH", inputKind: "target",
  },
  {
    id: "subdomain_enumeration", ordinal: 2, domain: "recon",
    nameEn: "Subdomain Enumeration Agent", nameAr: "وكيل اكتشاف النطاقات الفرعية",
    descriptionEn: "Discovers subdomains and related hostnames for a domain from passive sources and active queries.",
    descriptionAr: "اكتشاف النطاقات الفرعية وأسماء المضيفين لمرتبطة بالنطاق عبر مصادر سلبية واستعلامات نشطة.",
    capabilities: ["dns-discovery"], skills: ["subfinder"],
    requiredTools: K("subfinder"), permissions: ["network:scan"], riskLevel: "MEDIUM", inputKind: "target",
  },
  {
    id: "port_scanning", ordinal: 3, domain: "recon",
    nameEn: "Port Scanning Agent", nameAr: "وكيل فحص المنافذ",
    descriptionEn: "Systematic port and state detection across the target's address set.",
    descriptionAr: "فحص منتظم للمنافذ وحالتها عبر مجموعة عناوين الهدف.",
    capabilities: ["address-scan", "port-probe"], skills: ["nmap"],
    requiredTools: K("nmap"), permissions: ["network:scan"], riskLevel: "HIGH", inputKind: "target",
  },
  {
    id: "service_fingerprinting", ordinal: 4, domain: "recon",
    nameEn: "Service Fingerprinting Agent", nameAr: "وكيل بصمات الخدمات",
    descriptionEn: "Identifies running services and versions so follow-up tests target real product bugs, not guesses.",
    descriptionAr: "تحديد الخدمات والإصدارات قيد التشغيل كي تستهدف الاختبارات اللاحقة ثغرات منتجات حقيقية لا تخمينات.",
    capabilities: ["port-probe", "version-fingerprint"], skills: ["nmap"],
    requiredTools: K("nmap"), permissions: ["network:scan"], riskLevel: "MEDIUM", inputKind: "target",
  },
  {
    id: "asset_discovery", ordinal: 5, domain: "recon",
    nameEn: "Asset Discovery Agent", nameAr: "وكيل اكتشاف الأصول",
    descriptionEn: "Builds a consolidated asset inventory for the engagement scope from network and DNS sources.",
    descriptionAr: "بناء جرد أصول موحّد لنطاق التقييم من مصادر الشبكة والـ DNS.",
    capabilities: ["address-scan", "dns-discovery"], skills: ["nmap", "subfinder"],
    requiredTools: K("nmap", "subfinder"), permissions: ["network:scan"], riskLevel: "MEDIUM", inputKind: "target",
  },

  // ── OSINT ────────────────────────────────────────────────────────────────
  {
    id: "osint_operations", ordinal: 6, domain: "osint",
    nameEn: "OSINT Operations Agent", nameAr: "وكيل الاستخبارات مفتوحة المصدر",
    descriptionEn: "Open-source intelligence gathering over the engagement scope from public, cited sources.",
    descriptionAr: "جمع الاستخبارات مفتوحة المصدر لنطاق التقييم من مصادر عامة موثقة.",
    capabilities: ["osint-collection"], skills: ["subfinder"],
    requiredTools: K("subfinder"), permissions: ["network:scan"], riskLevel: "LOW", inputKind: "target",
  },
  {
    id: "email_enumeration", ordinal: 7, domain: "osint",
    nameEn: "Email Enumeration Agent", nameAr: "وكيل استطلاع البريد المؤسسي",
    descriptionEn: "Enumerates public organizational email-address patterns tied to the target domain.",
    descriptionAr: "استطلاع أنماط العناوين البريدية العامة المرتبطة بنطاق الهدف.",
    capabilities: ["osint-collection"], skills: ["subfinder"],
    requiredTools: K("subfinder"), permissions: ["network:scan"], riskLevel: "LOW", inputKind: "target",
  },
  {
    id: "dns_recon", ordinal: 8, domain: "osint",
    nameEn: "DNS Reconnaissance Agent", nameAr: "وكيل استطلاع الـ DNS",
    descriptionEn: "Census of DNS records and resolution behavior for the target's names.",
    descriptionAr: "جرد سجلات الـ DNS وسلوك التحليل لأسماء الهدف.",
    capabilities: ["dns-discovery"], skills: ["subfinder"],
    requiredTools: K("subfinder"), permissions: ["network:scan"], riskLevel: "LOW", inputKind: "target",
  },
  {
    id: "metadata_harvest", ordinal: 9, domain: "osint",
    nameEn: "Metadata Harvest Agent", nameAr: "وكيل استخراج البيانات الوصفية",
    descriptionEn: "Finds exposed metadata artefacts (documents, headers, profiles) for the scope and files them as findings.",
    descriptionAr: "رصد البيانات الوصفية المكشوفة (مستندات، ترويسات، نِسَب) للنطاق وتوثيقها كاكتشافات.",
    capabilities: ["artifact-discovery"], skills: ["nmap"],
    requiredTools: K("nmap"), permissions: ["network:scan"], riskLevel: "LOW", inputKind: "target",
  },
  {
    id: "public_exposure_scan", ordinal: 10, domain: "osint",
    nameEn: "Public Exposure Scan Agent", nameAr: "وكيل رصد التعرض العام",
    descriptionEn: "Sweeps the scope for services or data that should never be public and reports the exposure.",
    descriptionAr: "مسح النطاق بحثاً عن خدمات أو بيانات لا يفترض أن تكون عامة، وتبليغ التعرض.",
    capabilities: ["exposure-sweep", "port-probe"], skills: ["nmap", "subfinder"],
    requiredTools: K("nmap", "subfinder"), permissions: ["network:scan"], riskLevel: "MEDIUM", inputKind: "target",
  },

  // ── Web ──────────────────────────────────────────────────────────────────
  {
    id: "web_security", ordinal: 11, domain: "web",
    nameEn: "Web Security Agent", nameAr: "وكيل أمان الويب",
    descriptionEn: "Runs the web application security assessment over the scope and consolidates exploitable findings.",
    descriptionAr: "إدارة تقييم أمان تطبيقات الويب لنطاق الهدف وتجميع الاكتشافات القابلة للاستغلال.",
    capabilities: ["web-scan", "fuzz"], skills: ["nuclei", "zap"],
    requiredTools: K("nuclei", "zap"), permissions: ["network:scan", "web:test"], riskLevel: "HIGH", inputKind: "target",
  },
  {
    id: "api_security_testing", ordinal: 12, domain: "web",
    nameEn: "API Security Testing Agent", nameAr: "وكيل اختبار أمان الـ API",
    descriptionEn: "Tests API endpoints for auth, injection and data-exposure flaws starting from provided contracts or live targets.",
    descriptionAr: "اختبار نقاط الـ API بحثاً عن عيوب المصادقة والحقن وكشف البيانات انطلاقاً من عقود أو أهداف حية.",
    capabilities: ["web-scan", "dast"], skills: ["zap", "nuclei"],
    requiredTools: K("zap", "nuclei"), permissions: ["web:test"], riskLevel: "HIGH", inputKind: "target",
  },
  {
    id: "fuzzing_operations", ordinal: 13, domain: "web",
    nameEn: "Fuzzing Operations Agent", nameAr: "وكيل عمليات الـ Fuzzing",
    descriptionEn: "Feeds malformed and boundary inputs to the scope's endpoints and triages anomalous responses.",
    descriptionAr: "إطعام نقاط الهدف مدخلات معطّبة وحدية وفرز الاستجابات الشاذة.",
    capabilities: ["fuzz"], skills: ["nuclei", "zap"],
    requiredTools: K("nuclei", "zap"), permissions: ["web:test"], riskLevel: "HIGH", inputKind: "target",
  },
  {
    id: "web_app_audit", ordinal: 14, domain: "web",
    nameEn: "Web Application Audit Agent", nameAr: "وكيل تدقيق تطبيقات الويب",
    descriptionEn: "Full-stack review of the web application: DAST pass over behaviour plus OWASP-aligned categorization.",
    descriptionAr: "مراجعة شاملة للتطبيق الويب: جولة DAST على السلوك وتصنيف متوافق مع OWASP.",
    capabilities: ["dast", "web-scan"], skills: ["zap"],
    requiredTools: K("zap"), permissions: ["web:test"], riskLevel: "HIGH", inputKind: "target",
  },
  {
    id: "file_upload_analysis", ordinal: 15, domain: "web",
    nameEn: "File Upload Analysis Agent", nameAr: "وكيل تحليل رفع الملفات",
    descriptionEn: "Targets file-upload surfaces for type-confusion, path traversal and content-execution flaws.",
    descriptionAr: "استهداف أسطح رفع الملفات بحثاً عن عيوب خلط الأنواع وتجاوز المسارات وتنفيذ المحتوى.",
    capabilities: ["web-scan", "fuzz"], skills: ["zap", "nuclei"],
    requiredTools: K("zap", "nuclei"), permissions: ["web:test"], riskLevel: "HIGH", inputKind: "target",
  },

  // ── Validation ───────────────────────────────────────────────────────────
  {
    id: "vuln_analysis", ordinal: 16, domain: "validation",
    nameEn: "Vulnerability Analysis Agent", nameAr: "وكيل تحليل الثغرات",
    descriptionEn: "Merges findings from web, code and infrastructure passes into a single ranked vulnerability picture.",
    descriptionAr: "دمج اكتشافات الويب والكود والبنية في صورة ثغرات موحّدة ومرتبة.",
    capabilities: ["resp-docs", "evidence"], skills: ["nuclei", "semgrep"],
    requiredTools: K("nuclei", "semgrep"), permissions: ["read:findings"], riskLevel: "LOW", inputKind: "findings",
  },
  {
    id: "evidence_validation", ordinal: 17, domain: "validation",
    nameEn: "Evidence Validation Agent", nameAr: "وكيل التحقق من الأدلة",
    descriptionEn: "Re-derives each finding from its source evidence and rejects findings with no reproducible trace.",
    descriptionAr: "إعادة اشتقاق كل اكتشاف من أدلته المصدرية ورفض الاكتشافات بلا أثر قابل للتكرار.",
    capabilities: ["evidence"], skills: ["nuclei", "semgrep"],
    requiredTools: K("nuclei", "semgrep"), permissions: ["read:findings"], riskLevel: "LOW", inputKind: "evidence",
  },
  {
    id: "false_positive_reduction", ordinal: 18, domain: "validation",
    nameEn: "False Positive Reduction Agent", nameAr: "وكيل تقليل الإيجابيات الكاذبة",
    descriptionEn: "Cross-checks overlapping tool signals to tag and demote likely-false findings before reporting.",
    descriptionAr: "مقابلة إشارات الأدوات المتداخلة لتوسيم الاكتشافات الكاذبة المحتملة وخفض تصنيفها قبل التقرير.",
    capabilities: ["evidence", "resp-docs"], skills: ["nuclei", "semgrep"],
    requiredTools: K("nuclei", "semgrep"), permissions: ["read:findings"], riskLevel: "LOW", inputKind: "findings",
  },

  // ── Code ─────────────────────────────────────────────────────────────────
  {
    id: "code_security", ordinal: 19, domain: "code",
    nameEn: "Code Security Agent", nameAr: "وكيل أمان الكود",
    descriptionEn: "Scans the workspace source for vulnerabilities with a SAST engine and files code-level findings.",
    descriptionAr: "فحص شيفرة مساحة العمل بحثاً عن ثغرات عبر محرك SAST وتوثيق اكتشافات على مستوى الكود.",
    capabilities: ["code-analysis"], skills: ["semgrep"],
    requiredTools: K("semgrep"), permissions: ["read:code"], riskLevel: "MEDIUM", inputKind: "code",
  },
  {
    id: "dependency_audit", ordinal: 20, domain: "code",
    nameEn: "Dependency Audit Agent", nameAr: "وكيل تدقيق التبعيات",
    descriptionEn: "Audits third-party packages and images for known vulnerable versions and pins fixes.",
    descriptionAr: "تدقيق الحزم والصور الطرفية بحثاً عن إصدارات مُصابة معروفة وتثبيت الإصلاحات.",
    capabilities: ["dependency-check"], skills: ["trivy", "semgrep"],
    requiredTools: K("trivy", "semgrep"), permissions: ["read:code"], riskLevel: "MEDIUM", inputKind: "code",
  },
  {
    id: "secret_detection", ordinal: 21, domain: "code",
    nameEn: "Secret Detection Agent", nameAr: "وكيل كشف الأسرار",
    descriptionEn: "Scans the workspace for committed credentials, tokens and keys and reports the exposure.",
    descriptionAr: "فحص مساحة العمل بحثاً عن بيانات اعتماد ومفاتيح ملتزمة في الكود والتبليغ عن الكشف.",
    capabilities: ["code-analysis", "dependency-check"], skills: ["semgrep", "trivy"],
    requiredTools: K("semgrep", "trivy"), permissions: ["read:code"], riskLevel: "HIGH", inputKind: "code",
  },
  {
    id: "infrastructure_as_code_review", ordinal: 22, domain: "code",
    nameEn: "Infrastructure-as-Code Review Agent", nameAr: "وكيل مراجعة البنية ككود",
    descriptionEn: "Reviews IaC for misconfigurations that loosen isolation, grants or secrets handling.",
    descriptionAr: "مراجعة البنية ككود (IaC) بحثاً عن أخطاء تكوين تضعف العزل أو الصلاحيات أو معالجة الأسرار.",
    capabilities: ["code-analysis"], skills: ["semgrep"],
    requiredTools: K("semgrep"), permissions: ["read:code"], riskLevel: "MEDIUM", inputKind: "code",
  },
  {
    id: "secure_code_generation", ordinal: 23, domain: "code",
    nameEn: "Secure Code Generation Agent", nameAr: "وكيل توليد الكود الآمن",
    descriptionEn: "Generates or rewrites workspace code to fix a finding while keeping behaviour intact.",
    descriptionAr: "توليد أو إعادة كتابة الكود في مساحة العمل لإصلاح اكتشاف مع الحفاظ على السلوك.",
    capabilities: ["code-fix"], skills: ["semgrep"],
    requiredTools: K("semgrep"), permissions: ["read:code", "write:code"], riskLevel: "MEDIUM", inputKind: "code",
  },

  // ── Network ──────────────────────────────────────────────────────────────
  {
    id: "network_security", ordinal: 24, domain: "network",
    nameEn: "Network Security Agent", nameAr: "وكيل أمان الشبكة",
    descriptionEn: "Coordinates the network assessment: mapping, open services and exposure across the scope.",
    descriptionAr: "تنسيق تقييم الشبكة: رسم التضاريس، الخدمات المفتوحة، والتعرض عبر النطاق.",
    capabilities: ["address-scan", "port-probe"], skills: ["nmap", "nuclei"],
    requiredTools: K("nmap", "nuclei"), permissions: ["network:scan"], riskLevel: "HIGH", inputKind: "target",
  },
  {
    id: "traffic_analysis", ordinal: 25, domain: "network",
    nameEn: "Traffic Analysis Agent", nameAr: "وكيل تحليل حركة المرور",
    descriptionEn: "Profiles reachable services and response behaviour to find odd, verbose or leaky endpoints.",
    descriptionAr: "رسم صورة للخدمات القابلة للوصول وسلوك استجاباتها بحثاً عن نقاط شاذة أو مُسربة.",
    capabilities: ["port-probe", "version-fingerprint"], skills: ["nmap"],
    requiredTools: K("nmap"), permissions: ["network:scan"], riskLevel: "LOW", inputKind: "target",
  },
  {
    id: "perimeter_audit", ordinal: 26, domain: "network",
    nameEn: "Perimeter Audit Agent", nameAr: "وكيل تدقيق المحيط",
    descriptionEn: "Audits what the outside world can reach of the scope's perimeter and flags drift from policy.",
    descriptionAr: "تدقيق ما يستطيع الخارج الوصول إليه من محيط النطاق ورصد الانحراف عن السياسة.",
    capabilities: ["address-scan", "exposure-sweep"], skills: ["nmap", "nuclei"],
    requiredTools: K("nmap", "nuclei"), permissions: ["network:scan"], riskLevel: "MEDIUM", inputKind: "target",
  },
  {
    id: "protocol_tests", ordinal: 27, domain: "network",
    nameEn: "Protocol Tests Agent", nameAr: "وكيل اختبارات البروتوكول",
    descriptionEn: "Exercises application protocols for handshake, input and state flaws beyond plain port checks.",
    descriptionAr: "اختبار بروتوكولات التطبيق بحثاً عن عيوب في المصافحة والمدخلات والحالة أبعد من فحص المنافذ.",
    capabilities: ["web-scan", "port-probe"], skills: ["nmap", "zap"],
    requiredTools: K("nmap", "zap"), permissions: ["network:scan", "web:test"], riskLevel: "MEDIUM", inputKind: "target",
  },
  {
    id: "segmentation_check", ordinal: 28, domain: "network",
    nameEn: "Segmentation Check Agent", nameAr: "وكيل فحص التجزئة",
    descriptionEn: "Checks whether scope segments leak to one another beyond the intended boundaries.",
    descriptionAr: "التحقق من عدم تسرّب مقاطع النطاق إلى بعضها بما يتجاوز الحدود المقصودة.",
    capabilities: ["address-scan"], skills: ["nmap"],
    requiredTools: K("nmap"), permissions: ["network:scan"], riskLevel: "MEDIUM", inputKind: "target",
  },

  // ── Cloud ────────────────────────────────────────────────────────────────
  {
    id: "cloud_security", ordinal: 29, domain: "cloud",
    nameEn: "Cloud Security Agent", nameAr: "وكيل أمان السحابة",
    descriptionEn: "Audits the provisioned cloud posture against hardening baselines and policy.",
    descriptionAr: "تدقيق الوضع السحابي المُزوَّد مقابل خطوط الأساس للتحصين والسياسات.",
    capabilities: ["cloud-audit"], skills: ["prowler"],
    requiredTools: K("prowler"), permissions: ["read:config"], riskLevel: "MEDIUM", inputKind: "config",
  },
  {
    id: "iam_risk_assessment", ordinal: 30, domain: "cloud",
    nameEn: "IAM Risk Assessment Agent", nameAr: "وكيل تقييم مخاطر الهوية",
    descriptionEn: "Scores identity and access configuration for excessive grants and privilege sprawl.",
    descriptionAr: "تقييم تكوين الهوية والوصول بحثاً عن الصلاحيات المفرطة وتفشي الامتيازات.",
    capabilities: ["cloud-audit"], skills: ["prowler"],
    requiredTools: K("prowler"), permissions: ["read:config"], riskLevel: "HIGH", inputKind: "config",
  },
  {
    id: "csp_config_review", ordinal: 31, domain: "cloud",
    nameEn: "CSP Config Review Agent", nameAr: "وكيل مراجعة تكوين مزوّد السحابة",
    descriptionEn: "Reviews provider configuration surfaces (buckets, DNS, network) for public or weak settings.",
    descriptionAr: "مراجعة أسطح تكوين المزوّد (الدول، الـ DNS، الشبكة) بحثاً عن إعدادات عامة أو ضعيفة.",
    capabilities: ["cloud-audit", "artifact-discovery"], skills: ["prowler"],
    requiredTools: K("prowler"), permissions: ["read:config"], riskLevel: "MEDIUM", inputKind: "config",
  },
  {
    id: "cloud_exposure_analysis", ordinal: 32, domain: "cloud",
    nameEn: "Cloud Exposure Analysis Agent", nameAr: "وكيل تحليل الكشف السحابي",
    descriptionEn: "Correlates cloud findings with what is reachable from outside the perimeter.",
    descriptionAr: "ربط اكتشافات السحابة بما هو قابل للوصول من خارج المحيط.",
    capabilities: ["cloud-audit", "exposure-sweep"], skills: ["prowler", "nuclei"],
    requiredTools: K("prowler", "nuclei"), permissions: ["network:scan", "read:config"], riskLevel: "MEDIUM", inputKind: "config",
  },

  // ── Container ────────────────────────────────────────────────────────────
  {
    id: "container_security", ordinal: 33, domain: "container",
    nameEn: "Container Security Agent", nameAr: "وكيل أمان الحاويات",
    descriptionEn: "Scans images and runtime manifests for vulnerabilities, weak config and secrets.",
    descriptionAr: "فحص الصور وبيانات التشغيل بحثاً عن ثغرات وضعف تكوين وأسرار.",
    capabilities: ["dependency-check"], skills: ["trivy"],
    requiredTools: K("trivy"), permissions: ["read:config"], riskLevel: "MEDIUM", inputKind: "artifact",
  },
  {
    id: "kubernetes_audit", ordinal: 34, domain: "container",
    nameEn: "Kubernetes Audit Agent", nameAr: "وكيل تدقيق الشبكة",
    descriptionEn: "Audits Kubernetes manifests for privileged, over-granted or weakly isolated workloads.",
    descriptionAr: "تدقيق بيانات Kubernetes بحثاً عن أعباء عمل مميزة أو مفرطة الصلاحيات أو ضعيفة العزل.",
    capabilities: ["dependency-check", "config-audit"], skills: ["trivy"],
    requiredTools: K("trivy"), permissions: ["read:config"], riskLevel: "MEDIUM", inputKind: "config",
  },
  {
    id: "supply_chain_scan", ordinal: 35, domain: "container",
    nameEn: "Supply Chain Scan Agent", nameAr: "وكيل فحص سلسلة التوريد",
    descriptionEn: "Traces dependencies from manifest to image layers to catch poisoned or unpatched components.",
    descriptionAr: "تتبع التبعيات من البيان إلى طبقات الصورة لرصد المكونات الملوثة أو غير المحدّثة.",
    capabilities: ["dependency-check", "code-analysis"], skills: ["trivy", "semgrep"],
    requiredTools: K("trivy", "semgrep"), permissions: ["read:code", "read:config"], riskLevel: "HIGH", inputKind: "artifact",
  },
  {
    id: "image_hardening", ordinal: 36, domain: "container",
    nameEn: "Image Hardening Agent", nameAr: "وكيل تحصين الصور",
    descriptionEn: "Recommends and applies hardening for image size, privilege and cleanliness.",
    descriptionAr: "اقتراح وتنفيذ تحصين للصور من حيث الحجم والامتيازات والنظافة.",
    capabilities: ["dependency-check", "config-audit"], skills: ["trivy"],
    requiredTools: K("trivy"), permissions: ["read:config"], riskLevel: "MEDIUM", inputKind: "artifact",
  },

  // ── Forensics ────────────────────────────────────────────────────────────
  {
    id: "digital_forensics", ordinal: 37, domain: "forensics",
    nameEn: "Digital Forensics Agent", nameAr: "وكيل الطب الشرعي الرقمي",
    descriptionEn: "Coordinates evidence extraction and analysis from memory, logs and images.",
    descriptionAr: "تنسيق استخراج الأدلة وتحليلها من الذاكرة والسجلات والصور.",
    capabilities: ["memory-forensics"], skills: ["volatility"],
    requiredTools: K("volatility"), permissions: ["read:artifact"], riskLevel: "LOW", inputKind: "evidence",
  },
  {
    id: "memory_forensics", ordinal: 38, domain: "forensics",
    nameEn: "Memory Forensics Agent", nameAr: "وكيل تحليل الذاكرة",
    descriptionEn: "Analyzes memory images for processes, connections, injected code and artifacts of compromise.",
    descriptionAr: "تحليل صور الذاكرة بحثاً عن عمليات واتصالات وكود محقون وأدلة اختراق.",
    capabilities: ["memory-forensics"], skills: ["volatility"],
    requiredTools: K("volatility"), permissions: ["read:artifact"], riskLevel: "LOW", inputKind: "evidence",
  },
  {
    id: "artifact_triage", ordinal: 39, domain: "forensics",
    nameEn: "Artifact Triage Agent", nameAr: "وكيل فرز الأدلة",
    descriptionEn: "Prioritizes extracted evidence by relevance to the incident timeline and impact.",
    descriptionAr: "ترتيب الأدلة المستخرجة حسب صلتها بالخط الزمني للحادثة وأثرها.",
    capabilities: ["memory-forensics"], skills: ["volatility"],
    requiredTools: K("volatility"), permissions: ["read:artifact"], riskLevel: "LOW", inputKind: "evidence",
  },
  {
    id: "log_analysis", ordinal: 40, domain: "forensics",
    nameEn: "Log Analysis Agent", nameAr: "وكيل تحليل السجلات",
    descriptionEn: "Searches log surfaces for the signals that corroborate or refute a reported compromise.",
    descriptionAr: "البحث في أسطح السجلات عن إشارات تدعم أو تنفي الاختراق المُبلَّغ.",
    capabilities: ["log-correlation"], skills: ["nmap"],
    requiredTools: K("nmap"), permissions: ["network:scan", "read:artifact"], riskLevel: "LOW", inputKind: "evidence",
  },

  // ── Threat intelligence ──────────────────────────────────────────────────
  {
    id: "threat_intel", ordinal: 41, domain: "threat-intel",
    nameEn: "Threat Intelligence Agent", nameAr: "وكيل استخبارات التهديدات",
    descriptionEn: "Pulls cited threat intelligence relevant to the scope and aligns findings with it.",
    descriptionAr: "جلب استخبارات تهديدات موثقة ذات صلة بالنطاق ومواءمة الاكتشافات معها.",
    capabilities: ["threat-intel"], skills: ["subfinder", "nuclei"],
    requiredTools: K("subfinder", "nuclei"), permissions: ["network:scan"], riskLevel: "LOW", inputKind: "target",
  },
  {
    id: "ioc_enrichment", ordinal: 42, domain: "threat-intel",
    nameEn: "IOC Enrichment Agent", nameAr: "وكيل إثراء مؤشرات الاختراق",
    descriptionEn: "Enriches indicators with their public context and correlates them across the scope.",
    descriptionAr: "إثراء المؤشرات بسياقها العام وربطها عبر النطاق.",
    capabilities: ["threat-intel", "osint-collection"], skills: ["subfinder"],
    requiredTools: K("subfinder"), permissions: ["network:scan"], riskLevel: "LOW", inputKind: "evidence",
  },
  {
    id: "vulnerability_intel", ordinal: 43, domain: "threat-intel",
    nameEn: "Vulnerability Intelligence Agent", nameAr: "وكيل استخبارات الثغرات",
    descriptionEn: "Maps discovered versions and signals to known CVEs with severity and reachability notes.",
    descriptionAr: "ربط الإصدارات والإشارات المكتشفة بـ CVEs معروفة مع ملاحظات الخطورة وقابلية الوصول.",
    capabilities: ["threat-intel", "version-fingerprint"], skills: ["nuclei", "trivy"],
    requiredTools: K("nuclei", "trivy"), permissions: ["network:scan"], riskLevel: "LOW", inputKind: "target",
  },
  {
    id: "adversary_profiling", ordinal: 44, domain: "threat-intel",
    nameEn: "Adversary Profiling Agent", nameAr: "وكيل بناء صورة الخصم",
    descriptionEn: "Infers the likely attacker profile behind a pattern of exposed or exploited surfaces.",
    descriptionAr: "استنتاج ملف المهاجم المرجح خلف نمط من الأسطح المكشوفة أو المستغلة.",
    capabilities: ["threat-intel"], skills: ["nuclei"],
    requiredTools: K("nuclei"), permissions: ["network:scan"], riskLevel: "LOW", inputKind: "findings",
  },
  {
    id: "exposure_monitoring", ordinal: 45, domain: "threat-intel",
    nameEn: "Exposure Monitoring Agent", nameAr: "وكيل مراقبة التعرض الدائم",
    descriptionEn: "Re-checks the scope's attack surface over time and highlights what changed.",
    descriptionAr: "إعادة فحص سطح الهجوم للنطاق عبر الزمن وإبراز ما تغيّر.",
    capabilities: ["exposure-sweep", "address-scan"], skills: ["nmap", "nuclei"],
    requiredTools: K("nmap", "nuclei"), permissions: ["network:scan"], riskLevel: "MEDIUM", inputKind: "target",
  },

  // ── Remediation ──────────────────────────────────────────────────────────
  {
    id: "remediation", ordinal: 46, domain: "remediation",
    nameEn: "Remediation Agent", nameAr: "وكيل المعالجة",
    descriptionEn: "Turns validated findings into concrete, verifiable remediation steps or patches.",
    descriptionAr: "تحويل الاكتشافات الموثقة إلى خطوات معالجة ملموسة وقابلة للتحقق أو تصحيحات.",
    capabilities: ["code-fix", "resp-docs"], skills: ["semgrep"],
    requiredTools: K("semgrep"), permissions: ["read:findings", "write:code"], riskLevel: "MEDIUM", inputKind: "findings",
  },
  {
    id: "patch_strategy", ordinal: 47, domain: "remediation",
    nameEn: "Patch Strategy Agent", nameAr: "وكيل استراتيجية التصحيح",
    descriptionEn: "Plans sequenced remediation across findings by risk, dependency and blast radius.",
    descriptionAr: "التخطيط لمعالجة متسلسلة عبر الاكتشافات حسب الخطر والتبعيات ونصف قطر الأثر.",
    capabilities: ["resp-docs"], skills: ["semgrep"],
    requiredTools: K("semgrep"), permissions: ["read:findings"], riskLevel: "LOW", inputKind: "findings",
  },

  // ── Validation (runtime) ────────────────────────────────────────────────
  {
    id: "validation", ordinal: 48, domain: "validation",
    nameEn: "Validation Agent", nameAr: "وكيل التحقق",
    descriptionEn: "Validates findings against their evidence and the orbit of known-good behavior before release.",
    descriptionAr: "التحقق من الاكتشافات مقابل أدلتها وسلوك مدارها قبل الإفراج.",
    capabilities: ["evidence", "resp-docs"], skills: ["validation"],
    requiredTools: K("nuclei", "semgrep"), permissions: ["read:findings"], riskLevel: "LOW", inputKind: "findings",
  },

  // ── Reporting ────────────────────────────────────────────────────────────
  {
    id: "reporting", ordinal: 49, domain: "reporting",
    nameEn: "Reporting Agent", nameAr: "وكيل التقارير",
    descriptionEn: "Assembles validated findings into evidence-backed, readable engagement reports.",
    descriptionAr: "تجميع الاكتشافات الموثقة في تقارير تقييم مقروءة ومدعومة بالأدلة.",
    capabilities: ["resp-docs"], skills: ["reporting"],
    requiredTools: K("nuclei", "semgrep"), permissions: ["read:findings"], riskLevel: "LOW", inputKind: "findings",
  },

  // ── Testing ──────────────────────────────────────────────────────────────
  {
    id: "testing", ordinal: 50, domain: "testing",
    nameEn: "Testing Agent", nameAr: "وكيل الاختبار",
    descriptionEn: "Verifies that applied fixes hold by re-exercising the surface that failed before.",
    descriptionAr: "التحقق من ثبات الإصلاحات المُطبَّقة عبر إعادة اختبار السطح الذي فشل سابقاً.",
    capabilities: ["web-scan", "code-analysis"], skills: ["testing"],
    requiredTools: K("nuclei", "semgrep"), permissions: ["read:findings", "read:code"], riskLevel: "LOW", inputKind: "findings",
  },
];