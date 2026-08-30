import { OWASPItem, MitreTactic, CTFScenario } from '../types';

export const CODE_AUDIT_SAMPLES: {
  id: string;
  name: string;
  language: string;
  vulnerabilityType: string;
  code: string;
}[] = [
  {
    id: 'sqli-flask',
    name: 'Python Flask - ثغرة حقن قواعد البيانات (SQL Injection)',
    language: 'python',
    vulnerabilityType: 'SQL Injection (A03:2021)',
    code: `from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/api/user', methods=['GET'])
def get_user():
    username = request.args.get('username')
    # ثغرة أمنية حرجة: دمج المدخلات مباشرة في استعلام SQL دون تحصين (Unsanitized Concatenation)
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"user": user})
    return jsonify({"error": "User not found"}), 404`,
  },
  {
    id: 'cmd-injection-node',
    name: 'Node.js Express - حقن أوامر النظام (Command Injection)',
    language: 'javascript',
    vulnerabilityType: 'Command Injection (CWE-78)',
    code: `const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    // ثغرة خطيرة: تمرير مدخلات المستخدم مباشرة إلى دالة تنفيذ النظام exec
    // يمكن للمهاجم إرسال: 127.0.0.1; cat /etc/passwd
    exec(\`ping -c 3 \${host}\`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json({ output: stdout });
    });
});

app.listen(3000);`,
  },
  {
    id: 'jwt-auth-bypass',
    name: 'Node.js JWT - مصادقة غير آمنة وتخطي التحقق (Auth Bypass)',
    language: 'javascript',
    vulnerabilityType: 'Broken Authentication (A07:2021)',
    code: `const jwt = require('jsonwebtoken');

function verifyAdminToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).send('Access Denied');
    
    try {
        // ثغرة: فك التشفير دون التحقق من التوقيع أو قبول الخوارزمية 'none'
        const decoded = jwt.decode(token);
        if (decoded && decoded.role === 'admin') {
            req.user = decoded;
            return next();
        }
        return res.status(403).send('Forbidden');
    } catch (err) {
        return res.status(400).send('Invalid Token');
    }
}`,
  },
  {
    id: 'php-lfi',
    name: 'PHP - تضمين ملفات محلية (Local File Inclusion / LFI)',
    language: 'php',
    vulnerabilityType: 'Path Traversal / LFI (CWE-22)',
    code: `<?php
// ثغرة تضمين الملفات المحلية
$page = $_GET['page'];

if (isset($page)) {
    // تمرير المسار مباشرة دون فحص Whitelist أو استخدام basename
    // هجوم محتمل: ?page=../../../../etc/passwd
    include("templates/" . $page . ".php");
} else {
    include("templates/home.php");
}
?>`,
  },
  {
    id: 'dockerfile-insecure',
    name: 'Dockerfile - تشغيل كـ Root وممارسات تكوين غير آمنة',
    language: 'dockerfile',
    vulnerabilityType: 'Container Security Misconfiguration',
    code: `FROM node:18-alpine

WORKDIR /app

# نسخ الكود مع صلاحيات افتراضية لـ root
COPY . .

RUN npm install

# ثغرة: العمل بحساب root داخل الحاوية مما يسهل الـ Container Escape
# عدم استخدام Non-root USER
ENV SECRET_KEY="hardcoded_production_super_secret_key_123"

EXPOSE 3000
CMD ["npm", "start"]`,
  },
];

export const OWASP_TOP_10: OWASPItem[] = [
  {
    id: 'a01',
    code: 'A01:2021',
    titleAr: 'التحكم بالوصول المعطوب (Broken Access Control)',
    titleEn: 'Broken Access Control',
    descriptionAr: 'فشل التطبيق في فرض القيود على ما يمكن للمستخدمين المصرح لهم أو غير المصرح لهم القيام به، مما يسمح بالوصول لبيانات مستخدمين آخرين (IDOR) أو لوحات الإدارة.',
    descriptionEn: 'Restrictions on what authenticated users are allowed to do are not properly enforced, leading to unauthorized access and privilege escalation.',
    cweList: ['CWE-200', 'CWE-201', 'CWE-264', 'CWE-275', 'CWE-276', 'CWE-284', 'CWE-285', 'CWE-352'],
    impact: 'تسريب بيانات حساسة، تعديل بيانات المستخدمين، أو الاستيلاء على حسابات المشرفين.',
    prevention: 'تطبيق مبدأ أقل الصلاحيات (Least Privilege)، والتحقق من الصلاحيات على مستوى الخادم في كل مسار برمجي (Server-side RBAC).',
    exampleVulnerable: `// استعلام يعتمد فقط على المعرف من الرابط دون التحقق من هوية الجلسة
app.get('/api/invoice/:id', (req, res) => {
  const invoice = db.find({ id: req.params.id }); // ثغرة IDOR
  res.json(invoice);
});`,
    exampleFixed: `// التحقق من أن الفاتورة تخص المستخدم المسجل حالياً في الجلسة
app.get('/api/invoice/:id', authMiddleware, (req, res) => {
  const invoice = db.find({ id: req.params.id, userId: req.user.id });
  if (!invoice) return res.status(404).json({ error: 'Not found' });
  res.json(invoice);
});`,
  },
  {
    id: 'a02',
    code: 'A02:2021',
    titleAr: 'الفشل في التشفير (Cryptographic Failures)',
    titleEn: 'Cryptographic Failures',
    descriptionAr: 'استخدام خوارزميات تشفير ضعيفة أو قديمة (مثل MD5, SHA1, DES) أو عدم تشفير البيانات الحساسة أثناء النقل (TLS) أو التخزين.',
    descriptionEn: 'Previously known as Sensitive Data Exposure, focuses on failures related to cryptography which often lead to sensitive data exposure.',
    cweList: ['CWE-259', 'CWE-327', 'CWE-331'],
    impact: 'سرقة كلمات المرور، بيانات البطاقات الائتمانية، أو التنصت على حركة البيانات (Man-in-the-Middle).',
    prevention: 'استخدام خوارزميات قوية مثل Argon2 أو bcrypt لكلمات المرور، و AES-256-GCM للبيانات المخزنة، وتفعيل TLS 1.3 مع HSTS.',
    exampleVulnerable: `// استخدام MD5 لتخزين كلمات المرور (سهل الكسر جداً)
const hash = crypto.createHash('md5').update(password).digest('hex');`,
    exampleFixed: `// استخدام bcrypt مع Salt مناسب لحماية كلمات المرور
const hash = await bcrypt.hash(password, 12);`,
  },
  {
    id: 'a03',
    code: 'A03:2021',
    titleAr: 'هجمات الحقن (Injection)',
    titleEn: 'Injection (SQLi, NoSQL, OS Command, LDAP)',
    descriptionAr: 'تمرير بيانات غير موثوقة من المستخدم إلى مفسر الأوامر أو محرك قواعد البيانات كجزء من أمر أو استعلام دون تنقية أو استخدام استعلامات مجهزة.',
    descriptionEn: 'User-supplied data is not validated, filtered, or sanitized by the application before being sent to an interpreter.',
    cweList: ['CWE-77', 'CWE-78', 'CWE-79', 'CWE-88', 'CWE-89'],
    impact: 'قراءة أو تعديل أو حذف قواعد البيانات بالكامل، وتجاوز المصادقة، وتنفيذ أوامر خبيثة على الخادم.',
    prevention: 'استخدام الاستعلامات المجهزة المسبقة (Parameterized Queries / Prepared Statements) ومكتبات ORM آمنة وتجنب الدوال التنفيذية الخطيرة.',
    exampleVulnerable: `// دمج المتغير مباشرة في استعلام SQL
const sql = "SELECT * FROM users WHERE email = '" + email + "' AND pass = '" + pass + "'";
db.query(sql);`,
    exampleFixed: `// استخدام الاستعلام المجهز (Prepared Statement)
const sql = "SELECT * FROM users WHERE email = ? AND pass = ?";
db.query(sql, [email, hashedPass]);`,
  },
  {
    id: 'a04',
    code: 'A04:2021',
    titleAr: 'التصميم غير الآمن (Insecure Design)',
    titleEn: 'Insecure Design',
    descriptionAr: 'غياب نمذجة التهديدات (Threat Modeling) ومبادئ الأمان في التصميم المعماري للتطبيق منذ البداية، ولا يمكن إصلاحه بمجرد ترقيع الكود فقط.',
    descriptionEn: 'Focuses on risks related to design and architectural flaws, calling for more use of threat modeling and secure design patterns.',
    cweList: ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522'],
    impact: 'ثغرات هيكلية في منطق الأعمال (Business Logic Flaws) وعمليات الاسترجاع والشراء.',
    prevention: 'إدراج نمذجة التهديدات في دورة تطوير البرمجيات (SDLC) وتحديد حدود الثقة ومراجعة البنية التحتية.',
    exampleVulnerable: `// السماح بعدد لا نهائي من محاولات استرجاع كلمة المرور دون Rate Limiting
app.post('/api/reset-password-request', (req, res) => {
  sendResetEmail(req.body.email); // قابل للاستغلال في هجمات DoS أو Enumeration
});`,
    exampleFixed: `// تطبيق حد أقصى للطلبات (Rate Limit) ومطابقة معايير وقت الاستجابة
app.post('/api/reset-password-request', rateLimiter({ max: 3, windowMs: 15*60*1000 }), (req, res) => {
  handlePasswordResetGeneric(req.body.email);
  res.json({ message: 'If the email exists, a reset link was sent.' });
});`,
  },
  {
    id: 'a05',
    code: 'A05:2021',
    titleAr: 'التهيئة الأمنية الخاطئة (Security Misconfiguration)',
    titleEn: 'Security Misconfiguration',
    descriptionAr: 'ترك الإعدادات الافتراضية، أو الحسابات الافتراضية، أو فتح منافذ غير ضرورية، أو تمكين تصحيح الأخطاء (Debug Mode) في بيئة الإنتاج.',
    descriptionEn: 'Occurs when security settings are defined, implemented, and maintained as defaults or misconfigured in cloud or web servers.',
    cweList: ['CWE-16', 'CWE-2', 'CWE-11', 'CWE-13'],
    impact: 'كشف ملفات النظام، تفاصيل الأخطاء والمكتبات المستخدمة، وسهولة اختراق الخادم.',
    prevention: 'تطبيق خطوات Hardening صارمة، تعطيل رسائل الخطأ التفصيلية في الإنتاج، واستخدام Security Headers.',
    exampleVulnerable: `// في Express: ترك رأس X-Powered-By ومشاركة تفاصيل الخطأ في الاستجابة
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack }); // تسريب مسار الملفات وStack Trace
});`,
    exampleFixed: `// إخفاء رؤوس الخادم وتعميم رسائل الخطأ للعملاء
app.disable('x-powered-by');
app.use(helmet());
app.use((err, req, res, next) => {
  logger.error(err); // تسجيل الخطأ داخلياً بأمان
  res.status(500).json({ error: 'Internal server error' });
});`,
  },
];

export const MITRE_TACTICS: MitreTactic[] = [
  {
    id: 'TA0043',
    nameAr: 'الاستطلاع وجمع المعلومات (Reconnaissance)',
    nameEn: 'Reconnaissance',
    descriptionAr: 'جمع المعلومات الاستخبارية عن الهدف (شركات، نطاقات، عناوين IP، موظفين) لتخطيط الهجوم المستقبلي.',
    descriptionEn: 'Gathering credentials and information to plan future adversary operations.',
    techniques: [
      { id: 'T1595', name: 'Active Scanning', description: 'المسح النشط للمنافذ وخدمات الشبكة (Nmap, Masscan)', detection: 'مراقبة معدل اتصالات SYN وسجلات الـ Firewall.' },
      { id: 'T1596', name: 'Search Open Technical Databases', description: 'البحث في قواعد البيانات العامة مثل Shodan, Censys, WHOIS, DNS records', detection: 'صعب كشفه لأنه passive، ويتم عبر حماية أصول النطاق.' },
      { id: 'T1593', name: 'Search Open Websites/Domains', description: 'جمع بيانات OSINT من GitHub ومواقع التواصل الاجتماعي', detection: 'مراقبة تسريب مفاتيح API على المستودعات العامة (GitGuardian).' },
    ],
  },
  {
    id: 'TA0001',
    nameAr: 'الوصول الأولي (Initial Access)',
    nameEn: 'Initial Access',
    descriptionAr: 'التقنيات المستخدمة للحصول على موطئ قدم أولي داخل شبكة أو نظام الهدف.',
    descriptionEn: 'Techniques used to gain an initial foothold within a network.',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', description: 'استغلال ثغرة في تطبيق ويب أو خادم متصل بالإنترنت (Log4j, SQLi, RCE)', detection: 'تفعيل WAF ومراقبة طلبات الـ HTTP الشاذة.' },
      { id: 'T1566', name: 'Phishing', description: 'إرسال رسائل بريد إلكتروني احتيالية تحوي مرفقات أو روابط خبيثة', detection: 'مرشحات البريد (DMARC, DKIM, SPF) وتحليل المرفقات في Sandbox.' },
      { id: 'T1078', name: 'Valid Accounts', description: 'استخدام بيانات دخول مسروقة أو متوقعة للوصول الشرعي', detection: 'مراقبة تسجيل الدخول من مواقع جغرافية غير معتادة وتطبيق MFA.' },
    ],
  },
  {
    id: 'TA0002',
    nameAr: 'التنفيذ (Execution)',
    nameEn: 'Execution',
    descriptionAr: 'تشغيل أوامر وبرمجيات خبيثة على النظام المستهدف بعد الوصول إليه.',
    descriptionEn: 'Adversary-controlled code execution on local or remote systems.',
    techniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter', description: 'تنفيذ أوامر عبر PowerShell, Bash, Python, Windows CMD', detection: 'تفعيل PowerShell Script Block Logging ومراقبة العمليات الوليدة (Process Trees).' },
      { id: 'T1204', name: 'User Execution', description: 'إغراء المستخدم بالنقر على رابط أو ملف خبيث', detection: 'التدريب الأمني المستمر وتطبيق قيود Execution Policy.' },
    ],
  },
  {
    id: 'TA0004',
    nameAr: 'تصعيد الصلاحيات (Privilege Escalation)',
    nameEn: 'Privilege Escalation',
    descriptionAr: 'الارتقاء من حساب مستخدم عادي ذي صلاحيات محدودة إلى صلاحيات Administrator أو Root.',
    descriptionEn: 'Techniques used to gain higher-level permissions on a system.',
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism', description: 'استغلال ثغرات SUID binaries في لينكس أو ثغرات UAC في ويندوز', detection: 'تدقيق ملفات SUID دورياً ومنع المستخدمين العاديين من تشغيل sudo بدون كلمة مرور.' },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation', description: 'استغلال ثغرات في نواة النظام (Kernel Exploits مثل Dirty COW, Baron Samedit)', detection: 'تحديث وترقيع النواة وحزم النظام بشكل دوري.' },
    ],
  },
];

export const CTF_SCENARIOS: CTFScenario[] = [
  {
    id: 'ctf-01',
    titleAr: 'تحدي 1: تجاوز شاشة الدخول بحقن SQL',
    titleEn: 'Challenge 1: SQLi Login Bypass',
    category: 'Web',
    difficulty: 'Easy',
    descriptionAr: 'لديك صفحة تسجيل دخول إدارية لموقع شركة وهمية، تستخدم استعلام SQL ضعيف يدمج اسم المستخدم وكلمة المرور مباشرة.',
    descriptionEn: 'An administrative login form vulnerable to classical string concatenation SQL injection.',
    scenarioDetails: `كود التحقق في الخادم:
SELECT * FROM admin_users WHERE username = '$USER' AND password = '$PASSWORD'

الهدف: إيجاد حمولة (Payload) تجعل الشرط صحيحاً دائماً (True) لتسجيل الدخول كأدمن والحصول على العلم (Flag).`,
    hints: [
      'فكر في كيفية إغلاق علامة التنصيص الفردية \' والتعليق على باقي الاستعلام (-- أو #).',
      'تذكر أن: \' OR 1=1 -- تجعل الشرط صحيحاً دائماً.',
      'جرب إدخال: admin\' OR \'1\'=\'1 في حقل اسم المستخدم.',
    ],
    flag: 'FLAG{sqli_auth_bypass_mastered_2026}',
    solutionExplanation: 'عند إدخال `admin\' OR 1=1 --`، يتحول الاستعلام إلى `SELECT * FROM admin_users WHERE username = \'admin\' OR 1=1 -- AND password = \'...\'`، وبالتالي يتجاهل الخادم كلمة المرور لأن الشرط `1=1` صحيح ويعيد أول صف (المشرف).',
  },
  {
    id: 'ctf-02',
    titleAr: 'تحدي 2: فك تشفير البيانات المخفية واستخراج المفتاح',
    titleEn: 'Challenge 2: Multi-Layer Cryptanalysis',
    category: 'Crypto',
    difficulty: 'Easy',
    descriptionAr: 'تم اعتراض رسالة سرية مشفرة بـ Base64 ثم تم تحويلها إلى Hexadecimal. استخرج النص الأصلي ومفتاح العلم.',
    descriptionEn: 'An intercepted encoded payload with Hex and Base64 layering.',
    scenarioDetails: `السلسلة المشفرة:
526b7842523374755a585a6c636c39795a57783558323975583256755932396b6157356e58325a76636c397a5a574e31636d6c30655638794d44493266513d3d

الخطوة 1: فك تشفير Hex إلى نص.
الخطوة 2: فك تشفير ناتج الـ Base64 للحصول على FLAG{...}`,
    hints: [
      'استخدم أداة فك التشفير في صندوق الأدوات (Toolbox) لتحويل Hex إلى String أولاً.',
      'السلسلة الناتجة تبدأ بـ RkxBR... وهي Base64.',
      'فك تشفير الـ Base64 للوصول إلى العلم مباشرة.',
    ],
    flag: 'FLAG{never_rely_on_encoding_for_security_2026}',
    solutionExplanation: 'تحويل الـ Hex `526b7842...` ينتج `RkxBR3tuZXZlcl9yZWx5X29uX2VuY29kaW5nX2Zvcl9zZWN1cml0eV8yMDI2fQ==`، ثم فك تشفير Base64 يعطي العلم الصريح.',
  },
  {
    id: 'ctf-03',
    titleAr: 'تحدي 3: قراءة ملفات النظام عبر Path Traversal',
    titleEn: 'Challenge 3: LFI to System Flag',
    category: 'Web',
    difficulty: 'Medium',
    descriptionAr: 'موقع يعرض مقالات عبر المعامل `?view=about.html`. قم بالتنقل في مسار الملفات لقراءة ملف العلم الموجود في `/flag.txt`.',
    descriptionEn: 'A web viewer vulnerable to directory traversal allowing local system file read.',
    scenarioDetails: `المسار الافتراضي يبحث في:
/var/www/html/views/about.html

المطلوب: إرسال متسلسلة الرجوع للخلف (Directory Traversal) لقراءة \`/flag.txt\` في جذر النظام.`,
    hints: [
      'استخدم `../` للرجوع مجلد واحد للخلف.',
      'كم عدد المجلدات للوصول من `/var/www/html/views/` إلى الجذر `/`؟ (4 مرات على الأقل).',
      'جرب: `../../../../flag.txt`',
    ],
    flag: 'FLAG{lfi_path_traversal_restricted_roots}',
    solutionExplanation: 'تمرير `../../../../flag.txt` يخرج من مجلدات الويب ويصل إلى جذر نظام التشغيل ليقرأ الملف السري، والحل البرمجي هو استخدام `basename()` أو التحقق من `realpath()`.',
  },
];

export const COMMON_PORTS = [
  { port: 21, service: 'FTP', transport: 'TCP', risk: 'Medium', description: 'نقل الملفات غير المشفر (ينقل كلمات المرور بنص واضح).' },
  { port: 22, service: 'SSH', transport: 'TCP', risk: 'Low', description: 'الاتصال الآمن المشفر، هدف لهجمات Brute-Force.' },
  { port: 23, service: 'Telnet', transport: 'TCP', risk: 'High', description: 'بروتوكول قديم غير مشفر نهائياً (يجب إيقافه واستبداله بـ SSH).' },
  { port: 25, service: 'SMTP', transport: 'TCP', risk: 'Low', description: 'إرسال البريد الإلكتروني، يُفحص لثغرات Open Relay.' },
  { port: 53, service: 'DNS', transport: 'UDP/TCP', risk: 'Medium', description: 'ترجمة أسماء النطاقات، هدف لهجمات DNS Amplification و Zone Transfer.' },
  { port: 80, service: 'HTTP', transport: 'TCP', risk: 'Medium', description: 'تصفح الويب غير المشفر (يجب إعادة توجيهه لـ 443 HTTPS).' },
  { port: 443, service: 'HTTPS', transport: 'TCP', risk: 'Low', description: 'تصفح الويب المشفر باستخدام بروتوكول TLS.' },
  { port: 445, service: 'SMB', transport: 'TCP', risk: 'High', description: 'مشاركة الملفات في ويندوز، شهير بثغرات EternalBlue (MS17-010).' },
  { port: 1433, service: 'MS-SQL', transport: 'TCP', risk: 'High', description: 'قواعد بيانات Microsoft SQL Server.' },
  { port: 3306, service: 'MySQL', transport: 'TCP', risk: 'High', description: 'قواعد بيانات MySQL / MariaDB (يجب عدم كشفه للإنترنت العام).' },
  { port: 3389, service: 'RDP', transport: 'TCP', risk: 'High', description: 'سطح المكتب البعيد لويندوز، شهير بثغرات BlueKeep و Brute-force.' },
  { port: 5432, service: 'PostgreSQL', transport: 'TCP', risk: 'High', description: 'قواعد بيانات PostgreSQL.' },
  { port: 6379, service: 'Redis', transport: 'TCP', risk: 'Critical', description: 'تخزين الذاكرة المؤقتة، خطير جداً إن تُرِك بدون كلمة مرور (RCE).' },
  { port: 8080, service: 'HTTP-Alt / Proxy', transport: 'TCP', risk: 'Medium', description: 'خوادم الويب البديلة أو لوحات التحكم مثل Jenkins و Tomcat.' },
];

export const SUGGESTED_QUESTIONS = [
  'كيف أبدأ بتعلم اختبار الاختراق الأخلاقي (Roadmap للمبتدئين)؟',
  'اشرح لي آلية هجوم SQL Injection وكيف أحمي تطبيقي منه كلياً؟',
  'ما هو الفرق بين ثغرات XSS المخزنة (Stored) والمنعكسة (Reflected)؟',
  'كيف أستخدم أداة Nmap لفحص المنافذ واكتشاف إصدارات الخدمات بأمان؟',
  'اشرح لي هجوم Man-in-the-Middle وكيف يحمينا بروتوكول HTTPS/TLS؟',
  'ما هي أفضل المنهجيات المعتمدة لكتابة تقرير اختبار اختراق احترافي؟',
  'كيف أتعامل مع ثغرات الـ SSRF والوصول للخدمات الداخلية (Cloud Metadata)؟',
];
