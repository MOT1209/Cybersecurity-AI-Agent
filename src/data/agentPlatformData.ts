import { AgentMetadata, ToolPlugin, ProjectScope, LabEnvironment } from '../types';

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

export const TOOL_PLUGINS: ToolPlugin[] = [
  {
    id: 'nmap',
    name: 'Nmap Port & Service Scanner',
    category: 'Recon',
    descriptionAr: 'أداة مسح الشبكات وكشف المنافذ المفتوحة والخدمات وإصداراتها وأنظمة التشغيل.',
    descriptionEn: 'Network exploration tool and security/port scanner with service version fingerprinting.',
    version: '7.94-RELEASE',
    riskLevel: 'LOW',
    requiresHumanApproval: false,
    requiredPermissions: ['net:scan', 'port:discover'],
    timeoutSeconds: 30,
    inputSchema: {
      targetType: 'ip',
      sampleInput: '192.168.1.50',
      params: [
        { name: 'ports', type: 'string', defaultVal: '1-1000', description: 'Port range to inspect' },
        { name: 'timing', type: 'string', defaultVal: '-T4', description: 'Nmap timing template' }
      ]
    }
  },
  {
    id: 'nuclei',
    name: 'Nuclei Vulnerability Engine',
    category: 'Web',
    descriptionAr: 'ماسح سريع للثغرات مبني على قوالب مجتمعية لاكتشاف الأخطاء وتكوينات الويب غير الآمنة.',
    descriptionEn: 'Fast template-based vulnerability scanner for automated web and service security testing.',
    version: '3.1.8',
    riskLevel: 'MEDIUM',
    requiresHumanApproval: false,
    requiredPermissions: ['web:probe', 'cve:scan'],
    timeoutSeconds: 45,
    inputSchema: {
      targetType: 'url',
      sampleInput: 'http://192.168.1.50:8080',
      params: [
        { name: 'tags', type: 'string', defaultVal: 'cve,misconfig,exposure', description: 'Template tags to execute' }
      ]
    }
  },
  {
    id: 'subfinder',
    name: 'Subfinder Subdomain Recon',
    category: 'Recon',
    descriptionAr: 'أداة كشف النطاقات الفرعية السلبية (Passive Subdomain Discovery) عبر السجلات العامة.',
    descriptionEn: 'Fast passive subdomain discovery tool utilizing internet archives and OSINT feeds.',
    version: '2.6.4',
    riskLevel: 'SAFE',
    requiresHumanApproval: false,
    requiredPermissions: ['osint:dns'],
    timeoutSeconds: 20,
    inputSchema: {
      targetType: 'domain',
      sampleInput: 'corp-target.lab',
      params: []
    }
  },
  {
    id: 'semgrep',
    name: 'Semgrep SAST Code Engine',
    category: 'Code',
    descriptionAr: 'محرك التحليل الساكن للأكواد البرمجية لاكتشاف الثغرات وتطبيق قواعد الترميز الآمن.',
    descriptionEn: 'Lightweight static analysis engine for finding bugs, misconfigurations, and enforcing secure code rules.',
    version: '1.60.0',
    riskLevel: 'SAFE',
    requiresHumanApproval: false,
    requiredPermissions: ['code:read', 'sast:audit'],
    timeoutSeconds: 25,
    inputSchema: {
      targetType: 'code',
      sampleInput: 'def login(user, password): ...',
      params: [
        { name: 'ruleset', type: 'string', defaultVal: 'p/owasp-top-ten', description: 'Security ruleset to apply' }
      ]
    }
  },
  {
    id: 'trivy',
    name: 'Trivy Container & FS Scanner',
    category: 'Container',
    descriptionAr: 'أداة شاملة لفحص صور الحاويات وحزم البرمجيات واكتشاف ثغرات الـ CVE ومفاتيح التشفير.',
    descriptionEn: 'Comprehensive security scanner for container images, file systems, and Git repositories.',
    version: '0.49.1',
    riskLevel: 'LOW',
    requiresHumanApproval: false,
    requiredPermissions: ['container:inspect'],
    timeoutSeconds: 40,
    inputSchema: {
      targetType: 'container',
      sampleInput: 'app-web-server:latest',
      params: [
        { name: 'severity', type: 'string', defaultVal: 'CRITICAL,HIGH', description: 'Filter severity threshold' }
      ]
    }
  },
  {
    id: 'zap',
    name: 'OWASP ZAP Dynamic API Tester',
    category: 'Web',
    descriptionAr: 'فاحص ديناميكي لتطبيقات الويب (DAST) لاكتشاف ثغرات SQLi, XSS, و CSRF أثناء التشغيل.',
    descriptionEn: 'Dynamic application security testing (DAST) engine for active web scanning.',
    version: '2.14.0',
    riskLevel: 'HIGH',
    requiresHumanApproval: true,
    requiredPermissions: ['web:active_attack', 'dast:inject'],
    timeoutSeconds: 60,
    inputSchema: {
      targetType: 'url',
      sampleInput: 'http://192.168.1.50/login.php',
      params: [
        { name: 'attack_strength', type: 'string', defaultVal: 'Low', description: 'Attack depth in sandbox' }
      ]
    }
  },
  {
    id: 'prowler',
    name: 'Prowler Cloud Security Auditing',
    category: 'Cloud',
    descriptionAr: 'أداة تدقيق الأمان السحابي وفق معايير CIS Benchmarks و GDPR و NIST.',
    descriptionEn: 'Cloud security assessment and compliance tool for AWS, GCP, and Azure.',
    version: '3.11.0',
    riskLevel: 'MEDIUM',
    requiresHumanApproval: false,
    requiredPermissions: ['cloud:read_config'],
    timeoutSeconds: 45,
    inputSchema: {
      targetType: 'config',
      sampleInput: 'gcp-project-iam-policy.json',
      params: []
    }
  },
  {
    id: 'volatility',
    name: 'Volatility Memory Forensics Engine',
    category: 'Forensics',
    descriptionAr: 'تحليل صور الذاكرة العشوائية (RAM Dumps) لاستخراج العمليات المخفية وحقن الشيفرات.',
    descriptionEn: 'Advanced memory forensics framework for incident response and malware analysis.',
    version: '3.2.0',
    riskLevel: 'SAFE',
    requiresHumanApproval: false,
    requiredPermissions: ['forensics:memory'],
    timeoutSeconds: 50,
    inputSchema: {
      targetType: 'log',
      sampleInput: 'memory_dump_snapshot.raw',
      params: [
        { name: 'plugin', type: 'string', defaultVal: 'windows.pslist', description: 'Volatility plugin' }
      ]
    }
  }
];

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

export const LAB_ENVIRONMENTS: LabEnvironment[] = [
  {
    id: 'lab_vuln_shop',
    name: 'JuiceShop Microservices API Lab',
    category: 'Vulnerable App',
    difficulty: 'Intermediate',
    targetIp: '192.168.1.50',
    exposedPorts: [80, 8080, 3000, 3306],
    flag: 'CYBERGUARD{jwt_tamper_and_sqli_cracked_892}',
    description: 'تطبيق ويب للتجارة الإلكترونية يحتوي على ثغرات OWASP Top 10 (SQL Injection, Broken Object Level Auth, JWT Forgery).',
    dockerComposeHint: 'docker run -d -p 8080:3000 bkimminich/juice-shop',
    status: 'RUNNING'
  },
  {
    id: 'lab_k8s_escape',
    name: 'Kubernetes RBAC Misconfig & Container Escape',
    category: 'Container Escapes',
    difficulty: 'Advanced',
    targetIp: '192.168.1.51',
    exposedPorts: [6443, 2379, 10250],
    flag: 'CYBERGUARD{host_pid_and_docker_sock_escape_007}',
    description: 'بيئة حاويات مع امتيازات مفرطة لحاوية الويب تمكن من قراءة ملف docker.sock والسيطرة على الـ Host Node.',
    dockerComposeHint: 'docker-compose -f ./labs/k8s-escape/docker-compose.yml up -d',
    status: 'ISOLATED'
  },
  {
    id: 'lab_network_pcap',
    name: 'Internal Network Sniffing & Kerberos Golden Ticket',
    category: 'Network Defense',
    difficulty: 'Expert',
    targetIp: '10.0.0.12',
    exposedPorts: [88, 389, 445, 135],
    flag: 'CYBERGUARD{kerberos_golden_ticket_hash_dumped_991}',
    description: 'محاكاة لشبكة Active Directory مخترقة تتطلب تحليل حركة المرور عبر Zeek/Wireshark واستخراج التذاكر المشفرة.',
    dockerComposeHint: 'docker run -d --net=isolated-corp ad-sim:v2.1',
    status: 'STOPPED'
  }
];
