import { AgentMetadata, ProjectScope } from '../types';

export const SYSTEM_AGENTS: AgentMetadata[] = [
  {
    id: 'recon',
    nameEn: 'Reconnaissance Agent',
    nameAr: 'وكيل الاستطلاع وكشف الأصول',
    roleDescriptionEn: 'Asset discovery, port scanning, DNS intelligence, subdomain enumeration, tech-stack fingerprinting.',
    roleDescriptionAr: 'اكتشاف الأصول والمنافذ المفتوحة، تحليل نطاقات DNS، كشف التقنيات ومخطط الهدف.',
    icon: 'Radar',
    badgeColor: 'text-cyan-400 border-cyan-500/30 bg-cyan-950/40',
    tools: ['Nmap', 'Subfinder', 'Amass', 'DNSx', 'Wappalyzer'],
    capabilities: ['Active Port Discovery', 'Passive DNS Recon', 'Subdomain Mapping', 'Service Fingerprinting'],
    systemPrompt: 'You are the Reconnaissance Agent. Focus strictly on asset mapping, open ports, banners, and domain infrastructure within authorized scope.'
  },
  {
    id: 'web_security',
    nameEn: 'Web Security Agent',
    nameAr: 'وكيل أمان تطبيقات الويب',
    roleDescriptionEn: 'Authorized web application penetration testing, API vulnerability discovery, OWASP Top 10 analysis.',
    roleDescriptionAr: 'فحص ثغرات تطبيقات الويب وواجهات البرمجة (APIs)، وتدقيق معايير OWASP Top 10.',
    icon: 'Globe',
    badgeColor: 'text-indigo-400 border-indigo-500/30 bg-indigo-950/40',
    tools: ['OWASP ZAP', 'Burp Suite API', 'Nuclei', 'Katana', 'ffuf'],
    capabilities: ['SQLi & XSS Detection', 'SSRF & CSRF Probing', 'Authentication Bypass Checks', 'API Schema Auditing'],
    systemPrompt: 'You are the Web Security Agent. Specialize in web protocols, HTTP headers, authentication workflows, and injection vectors.'
  },
  {
    id: 'vuln_analysis',
    nameEn: 'Vulnerability Analysis Agent',
    nameAr: 'وكيل تحليل الثغرات والربط',
    roleDescriptionEn: 'Vulnerability correlation, CVE/CWE mapping, CVSS score evaluation, finding validation & false-positive filtering.',
    roleDescriptionAr: 'تحليل الثغرات وربطها بقواعد CVE و CWE، تقييم درجات خطورة CVSS v3.1 وفلترة الإيجابيات الكاذبة.',
    icon: 'ShieldAlert',
    badgeColor: 'text-rose-400 border-rose-500/30 bg-rose-950/40',
    tools: ['NVD Feeds', 'Vulners API', 'Exploit-DB Mapping', 'CVSS Calculator'],
    capabilities: ['CVE Correlation', 'CWE Classification', 'Evidence Verification', 'False Positive Elimination'],
    systemPrompt: 'You are the Vulnerability Analysis Agent. Validate raw tool outputs, assess true exploitability, calculate accurate CVSS scores.'
  },
  {
    id: 'code_security',
    nameEn: 'Code Security Agent (SAST/SCA)',
    nameAr: 'وكيل أمان الشيفرات البرمجية',
    roleDescriptionEn: 'Static code analysis, secret leak scanning, dependency vulnerability triage, secure coding remediation.',
    roleDescriptionAr: 'تدقيق الأكواد المصدرية (SAST)، اكتشاف الأسرار المسربة، وفحص الثغرات في المكتبات والتبعيات (SCA).',
    icon: 'Code2',
    badgeColor: 'text-emerald-400 border-emerald-500/30 bg-emerald-950/40',
    tools: ['Semgrep', 'Bandit', 'CodeQL Engine', 'Trivy FS', 'Gitleaks'],
    capabilities: ['SAST Rule Execution', 'Hardcoded Secret Audit', 'Dependency SCA', 'Refactored Patching'],
    systemPrompt: 'You are the Code Security Agent. Inspect source code patterns, identify dangerous sinks and functions, generate safe patches.'
  },
  {
    id: 'network_security',
    nameEn: 'Network Security Agent',
    nameAr: 'وكيل أمان وحركة الشبكات',
    roleDescriptionEn: 'Packet inspection, protocol anomaly triage, network segmentation validation, unencrypted traffic detection.',
    roleDescriptionAr: 'تحليل حزم الشبكة (PCAP)، رصد التشويه في البروتوكولات، والتحقق من التشفير وعزل الشبكات.',
    icon: 'Network',
    badgeColor: 'text-blue-400 border-blue-500/30 bg-blue-950/40',
    tools: ['Wireshark Engine', 'tcpdump Sandbox', 'TShark', 'Zeek Core'],
    capabilities: ['Packet Dissection', 'Cleartext Credential Flagging', 'Traffic Flow Anomaly', 'TLS Audit'],
    systemPrompt: 'You are the Network Security Agent. Analyze network traces, dissect packets, and uncover protocol weaknesses.'
  },
  {
    id: 'cloud_security',
    nameEn: 'Cloud Security Agent',
    nameAr: 'وكيل أمان البيئات السحابية',
    roleDescriptionEn: 'Cloud configuration assessment, IAM privilege inspection, storage bucket permissions, compliance posture.',
    roleDescriptionAr: 'تدقيق تكوينات السحابة (AWS/GCP/Azure)، فحص صلاحيات IAM المفرطة وتأمين حاويات التخزين.',
    icon: 'Cloud',
    badgeColor: 'text-sky-400 border-sky-500/30 bg-sky-950/40',
    tools: ['Prowler Core', 'ScoutSuite', 'CloudMapper', 'IAM Policy Validator'],
    capabilities: ['IAM Least Privilege Audit', 'S3/GCS Public Bucket Detection', 'Security Group Audit', 'CIS Benchmark'],
    systemPrompt: 'You are the Cloud Security Agent. Evaluate cloud infrastructure posture, misconfigurations, and privilege escalations.'
  },
  {
    id: 'container_security',
    nameEn: 'Container & K8s Agent',
    nameAr: 'وكيل أمان الحاويات وكوبرنيتس',
    roleDescriptionEn: 'Docker image vulnerability scanning, Kubernetes RBAC auditing, runtime container escape checks.',
    roleDescriptionAr: 'فحص صور Docker وثغرات طبقات الحاويات، وتدقيق سياسات ومجموعات Kubernetes.',
    icon: 'Boxes',
    badgeColor: 'text-amber-400 border-amber-500/30 bg-amber-950/40',
    tools: ['Trivy Container', 'Kube-bench', 'Dockle', 'Hadolint'],
    capabilities: ['Base Image CVE Scan', 'Docker Socket Exposure Check', 'Privileged Container Detection', 'K8s RBAC Audit'],
    systemPrompt: 'You are the Container Security Agent. Audit Dockerfiles, container layers, and Kubernetes cluster security controls.'
  },
  {
    id: 'digital_forensics',
    nameEn: 'Digital Forensics Agent',
    nameAr: 'وكيل الأدلة الجنائية الرقمية',
    roleDescriptionEn: 'Artifact analysis, memory dump analysis, event log reconstruction, incident timeline synthesis.',
    roleDescriptionAr: 'تحليل الآثار الرقمية وسجلات الأحداث (Logs)، فحص تفريغ الذاكرة، وبناء الخط الزمني للحوادث.',
    icon: 'FileSearch',
    badgeColor: 'text-purple-400 border-purple-500/30 bg-purple-950/40',
    tools: ['Volatility Core', 'LogParser', 'Syslog Analyzer', 'TimelineBuilder'],
    capabilities: ['Log Correlation', 'Persistence Mechanism Detection', 'Memory Artifact Extraction', 'Incident Timeline'],
    systemPrompt: 'You are the Digital Forensics Agent. Extract digital artifacts, reconstruct incident chronologies, and locate IoCs.'
  },
  {
    id: 'threat_intel',
    nameEn: 'Threat Intelligence Agent',
    nameAr: 'وكيل استخبارات التهديدات',
    roleDescriptionEn: 'IOC lookup, MITRE ATT&CK enterprise mapping, threat actor profiling, threat feed correlation.',
    roleDescriptionAr: 'تحليل مؤشرات الاختراق (IoCs)، ربط التهديدات بإطار عمل MITRE ATT&CK، وتتبع سلوك المهاجمين.',
    icon: 'Crosshair',
    badgeColor: 'text-red-400 border-red-500/30 bg-red-950/40',
    tools: ['MITRE Matrix API', 'AlienVault OTX Connector', 'VirusTotal Engine', 'MISP Feed'],
    capabilities: ['IoC Reputation Query', 'Tactic & Technique Tagging', 'Adversary Profiling', 'Defensive Detection Rules'],
    systemPrompt: 'You are the Threat Intel Agent. Map identified adversary behaviors to MITRE ATT&CK techniques and enrich IoCs.'
  },
  {
    id: 'remediation',
    nameEn: 'Remediation & Hardening Agent',
    nameAr: 'وكيل الترقيع والتحصين الأمني',
    roleDescriptionEn: 'Converting findings to secure configurations, code patches, defensive rules, and verification steps.',
    roleDescriptionAr: 'تحويل الثغرات إلى حلول ترقيع عملية، وتوليد شيفرات آمنة وقواعد جدار ناري وإرشادات التحصين.',
    icon: 'Wrench',
    badgeColor: 'text-teal-400 border-teal-500/30 bg-teal-950/40',
    tools: ['Patch Generator', 'Config Hardener', 'WAF Rule Synthesizer', 'Verification Script Builder'],
    capabilities: ['Automated Code Patching', 'Hardening Script Generation', 'ModSecurity & CSP Rules', 'Retest Guidance'],
    systemPrompt: 'You are the Remediation Agent. Formulate clear, verified, and testable code fixes and infrastructure hardening steps.'
  },
  {
    id: 'reporting',
    nameEn: 'Executive & Tech Reporting Agent',
    nameAr: 'وكيل صياغة التقارير التنفيذية والفنية',
    roleDescriptionEn: 'Synthesizing findings into executive summaries, detailed technical assessments, and exportable documentation.',
    roleDescriptionAr: 'صياغة تقارير شاملة متوافقة مع معايير PTES و NIST، وتصديرها بصيغ Markdown و HTML و JSON.',
    icon: 'FileText',
    badgeColor: 'text-violet-400 border-violet-500/30 bg-violet-950/40',
    tools: ['Markdown Engine', 'HTML Report Generator', 'CVSS Visualizer', 'PDF Formatter'],
    capabilities: ['Executive Summary Synthesis', 'Risk Matrix Visuals', 'Compliance Audit Trails', 'Multi-format Export'],
    systemPrompt: 'You are the Reporting Agent. Author clean, rigorous, and professional penetration testing & security assessment reports.'
  },
  {
    id: 'testing',
    nameEn: 'Self-Testing & Security QA Agent',
    nameAr: 'وكيل اختبار المنصة والتحقق الأمني',
    roleDescriptionEn: 'Internal validation of platform defenses, prompt injection resistance, permission sandbox verification.',
    roleDescriptionAr: 'فحص واختبار دفاعات المنصة ذاتياً ضد حقن الأوامر، وتخطي الصلاحيات، وتسريب المفاتيح.',
    icon: 'CheckCheck',
    badgeColor: 'text-emerald-500 border-emerald-500/30 bg-emerald-950/40',
    tools: ['Prompt Armor Tester', 'Gateway Boundary Fuzzer', 'Sandbox Jailbreak Check', 'Scope Breach Validator'],
    capabilities: ['Prompt Injection Defense Check', 'Scope Boundary Enforcement', 'Tool Permission Audit', 'Secret Leak Prevention'],
    systemPrompt: 'You are the Platform Testing Agent. Continuously audit security controls, authorization gates, and prompt guards.'
  }
];

/**
 * NOTE: TOOL_PLUGINS and LAB_ENVIRONMENTS used to live here as static arrays
 * claiming tools were "Installed" and labs were "RUNNING". Nothing rendered
 * them, and nothing verified them. The real state now comes from the backend:
 *   tools -> GET /api/tools/health  (verified adapter + sandbox + image state)
 *   agents -> GET /api/agents       (only agents the orchestrator can dispatch)
 * Labs have no backend yet, so there is deliberately no catalog to display.
 */


export const INITIAL_PROJECT_SCOPES: ProjectScope[] = [
  {
    id: 'proj_alpha_lab',
    name: 'Authorized Enterprise Staging Lab',
    targetDomain: 'target-corp.lab',
    targetIps: ['192.168.1.50', '192.168.1.51', '10.0.0.12', '127.0.0.1'],
    environmentType: 'Production Lab',
    authorizationGrantedBy: 'Chief Information Security Officer (CISO) - Letter of Engagement #2026-ENG-089',
    authorizationDate: '2026-08-01',
    validUntil: '2026-12-31',
    inScope: [
      '192.168.1.50 (Web & API Server)',
      '192.168.1.51 (Database & Auth Gateway)',
      '*.target-corp.lab',
      'http://192.168.1.50:8080/api/v1/*'
    ],
    outOfScope: [
      '192.168.1.1 (Core Gateway Router)',
      'production-billing.target-corp.com',
      'Third-party cloud infrastructure (AWS/GCP accounts outside lab scope)'
    ],
    policy: {
      allowedTargets: ['192.168.1.50', '192.168.1.51', '10.0.0.12', '127.0.0.1', 'target-corp.lab'],
      deniedTargets: ['192.168.1.1', '8.8.8.8', 'production-billing.target-corp.com'],
      maxScanConcurrency: 3,
      requireApprovalForHighRisk: true,
      strictSandboxEnforced: true,
      auditLoggingEnabled: true
    }
  },
  {
    id: 'proj_ctf_sandbox',
    name: 'Isolated CTF Arena & Vulnerable VM',
    targetDomain: 'ctf-arena.local',
    targetIps: ['172.20.0.2', '172.20.0.3', '127.0.0.1'],
    environmentType: 'CTF Arena',
    authorizationGrantedBy: 'CyberGuard Training Sandbox Admin',
    authorizationDate: '2026-08-20',
    validUntil: '2027-01-01',
    inScope: ['172.20.0.0/24 (Docker Virtual Subnet)', 'ctf-arena.local', 'localhost:3000'],
    outOfScope: ['Host Operating System', 'External Public Internet'],
    policy: {
      allowedTargets: ['172.20.0.2', '172.20.0.3', '127.0.0.1', 'localhost', 'ctf-arena.local'],
      deniedTargets: ['*'],
      maxScanConcurrency: 5,
      requireApprovalForHighRisk: false,
      strictSandboxEnforced: true,
      auditLoggingEnabled: true
    }
  }
];
