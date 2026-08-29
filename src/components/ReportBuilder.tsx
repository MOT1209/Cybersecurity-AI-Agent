import React, { useState } from 'react';
import { apiFetch } from '../lib/api';
import { 
  FileText, 
  Sparkles, 
  Download, 
  Copy, 
  Check, 
  ShieldAlert, 
  Plus, 
  Trash2,
  RefreshCw,
  Building,
  UserCheck
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { SecurityReportFinding } from '../types';

interface ReportBuilderProps {
  language: 'ar' | 'en';
}

export const ReportBuilder: React.FC<ReportBuilderProps> = ({ language }) => {
  const isAr = language === 'ar';
  const [targetName, setTargetName] = useState<string>('شركة التقنية الآمنة المحدودة (TechSafe Portal)');
  const [scope, setScope] = useState<string>('اختبار اختراق تطبيقات الويب (Black-Box Web Application Penetration Test)');
  const [testerName, setTesterName] = useState<string>('CyberAgent Certified Penetration Tester');
  const [findings, setFindings] = useState<SecurityReportFinding[]>([
    {
      id: 'f-1',
      title: 'SQL Injection in User Authentication API',
      severity: 'CRITICAL',
      cwe: 'CWE-89',
      affectedAsset: '/api/v1/auth/login',
      description: 'تم اكتشاف ثغرة حقن SQL تمكن المهاجم من تخطي شاشة الدخول والوصول لصلاحيات المشرف دون كلمة مرور.',
      remediation: 'استخدام الاستعلامات المجهزة المسبقة (Parameterized Queries) والتحقق الصارم من المدخلات.',
    },
    {
      id: 'f-2',
      title: 'Broken Access Control (IDOR) in Invoices',
      severity: 'HIGH',
      cwe: 'CWE-639',
      affectedAsset: '/api/v1/invoices/:id',
      description: 'فشل التحقق من ملكية الفاتورة يسمح لأي مستخدم عادي باستعراض فواتير العملاء الآخرين عبر تغيير المعرف الرقمي.',
      remediation: 'ربط الاستعلام بجلسة المستخدم الحالية في قاعدة البيانات والتحقق من الصلاحيات.',
    },
    {
      id: 'f-3',
      title: 'Missing Security Headers (HSTS, CSP, X-Frame-Options)',
      severity: 'LOW',
      cwe: 'CWE-1021',
      affectedAsset: 'Global Web Headers',
      description: 'غياب رؤوس الحماية الأساسية يترك التطبيق عرضة لهجمات Clickjacking وخفض مستوى تشفير الاتصال.',
      remediation: 'تكوين خادم الويب لتمرير رؤوس Strict-Transport-Security و Content-Security-Policy.',
    },
  ]);

  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('MEDIUM');
  const [newAsset, setNewAsset] = useState('');

  const [loading, setLoading] = useState<boolean>(false);
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);

  const handleAddFinding = () => {
    if (!newTitle.trim()) return;
    const item: SecurityReportFinding = {
      id: `f-${Date.now()}`,
      title: newTitle.trim(),
      severity: newSeverity,
      cwe: 'CWE-Misc',
      affectedAsset: newAsset.trim() || 'General Endpoint',
      description: isAr ? 'تم رصد هذا الخلل أثناء فحص أمان التطبيق.' : 'Observed during application security evaluation.',
      remediation: isAr ? 'مراجعة الكود وتطبيق الممارسات الأمنية المعتمدة.' : 'Review code and apply secure coding practices.',
    };
    setFindings((prev) => [...prev, item]);
    setNewTitle('');
    setNewAsset('');
  };

  const handleRemoveFinding = (id: string) => {
    setFindings((prev) => prev.filter((f) => f.id !== id));
  };

  const handleGenerateReport = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/api/gemini/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetName,
          scope,
          testerName,
          findings,
        }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setReportMarkdown(data.reportMarkdown);
    } catch (err: any) {
      console.error('Report generation error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadMarkdown = () => {
    if (!reportMarkdown) return;
    const blob = new Blob([reportMarkdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Security-Assessment-Report-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col gap-5">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-slate-900/90 border border-slate-800 rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-purple-950/80 border border-purple-800/60 text-purple-400">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>{isAr ? 'منشئ تقارير اختبار الاختراق الرسمية' : 'Executive Security Report Generator'}</span>
            </h2>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'أنشئ تقارير احترافية موثقة للإدارة العليا والفرق التقنية تشمل ملخص المخاطر، والنتائج، وخطة الترقيع.'
                : 'Generate comprehensive executive and technical pentest reports with CVSS metrics and remediation roadmaps.'}
            </p>
          </div>
        </div>

        <button
          onClick={handleGenerateReport}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs shadow-lg shadow-purple-950 disabled:opacity-50 transition-all"
        >
          {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
          <span>{loading ? (isAr ? 'جاري صياغة التقرير...' : 'Drafting Report...') : (isAr ? 'توليد التقرير الذكي' : 'Generate Full Report')}</span>
        </button>
      </div>

      {/* Grid: Form & Findings on Left, Generated Report Preview on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Form: Config & Findings */}
        <div className="lg:col-span-5 flex flex-col gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              {isAr ? 'معلومات التقييم والنطاق:' : 'Assessment Scope & Metadata:'}
            </h3>

            <div className="flex flex-col gap-1">
              <label className="text-[11px] text-slate-400">{isAr ? 'اسم الهدف / العميل:' : 'Target Organization:'}</label>
              <input
                type="text"
                value={targetName}
                onChange={(e) => setTargetName(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-700"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-[11px] text-slate-400">{isAr ? 'نطاق الفحص (Scope):' : 'Assessment Scope:'}</label>
              <input
                type="text"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-700"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-[11px] text-slate-400">{isAr ? 'المختبر المسؤول:' : 'Lead Auditor Name:'}</label>
              <input
                type="text"
                value={testerName}
                onChange={(e) => setTesterName(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-700"
              />
            </div>
          </div>

          {/* Findings List Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                {isAr ? 'قائمة الثغرات المرصودة:' : 'Logged Findings:'}
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-purple-300">
                {findings.length} findings
              </span>
            </div>

            <div className="flex flex-col gap-2 max-h-56 overflow-y-auto">
              {findings.map((f) => (
                <div key={f.id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-2">
                  <div className="flex flex-col overflow-hidden">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.2 rounded ${
                          f.severity === 'CRITICAL'
                            ? 'bg-red-950 text-red-400'
                            : f.severity === 'HIGH'
                            ? 'bg-orange-950 text-orange-400'
                            : 'bg-amber-950 text-amber-400'
                        }`}
                      >
                        {f.severity}
                      </span>
                      <span className="text-xs font-semibold text-slate-200 truncate">{f.title}</span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono truncate">{f.affectedAsset}</span>
                  </div>

                  <button
                    onClick={() => handleRemoveFinding(f.id)}
                    className="text-slate-500 hover:text-rose-400 p-1 flex-shrink-0"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>

            {/* Quick Add Finding Bar */}
            <div className="pt-2 border-t border-slate-800 flex flex-col gap-2">
              <span className="text-[11px] font-semibold text-slate-400">{isAr ? 'إضافة نتيجة سريعة:' : 'Quick Add Finding:'}</span>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder={isAr ? 'عنوان الثغرة...' : 'Finding title...'}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none"
                />
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as any)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
                <button
                  onClick={handleAddFinding}
                  disabled={!newTitle.trim()}
                  className="p-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white disabled:opacity-40"
                >
                  <Plus className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right Preview: Generated Report View */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col gap-3 min-h-[500px]">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <FileText className="w-4 h-4 text-purple-400" />
              <span>{isAr ? 'معاينة التقرير النهائي (Markdown Document)' : 'Generated Report Document'}</span>
            </h3>

            {reportMarkdown && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(reportMarkdown);
                    setCopiedReport(true);
                    setTimeout(() => setCopiedReport(false), 2000);
                  }}
                  className="flex items-center gap-1 text-xs text-slate-300 hover:text-purple-300 px-2 py-1 rounded bg-slate-950 border border-slate-800"
                >
                  {copiedReport ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedReport ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  onClick={handleDownloadMarkdown}
                  className="flex items-center gap-1 text-xs text-purple-300 hover:text-purple-200 px-2.5 py-1 rounded bg-purple-950/60 border border-purple-800/80"
                >
                  <Download className="w-3 h-3" />
                  <span>{isAr ? 'تحميل .md' : 'Download .md'}</span>
                </button>
              </div>
            )}
          </div>

          <div className="flex-1 overflow-y-auto max-h-[600px] p-4 bg-slate-950/80 rounded-xl border border-slate-800/60 text-slate-200 text-xs leading-relaxed">
            {loading ? (
              <div className="h-full flex flex-col items-center justify-center py-20 text-center">
                <div className="w-10 h-10 rounded-full border-2 border-purple-500/20 border-t-purple-400 animate-spin mb-3" />
                <p className="text-xs font-semibold text-slate-300">
                  {isAr ? 'يقوم وكيل الـ AI بصياغة وتنسيق التقرير الرسمي...' : 'AI Agent is assembling formal executive report...'}
                </p>
              </div>
            ) : reportMarkdown ? (
              <div className="prose prose-invert max-w-none text-xs">
                <ReactMarkdown>{reportMarkdown}</ReactMarkdown>
              </div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center py-20 text-center text-slate-500">
                <FileText className="w-12 h-12 text-slate-800 mb-2" />
                <p className="text-xs text-slate-400">
                  {isAr ? 'اضغط على زر "توليد التقرير الذكي" لإنشاء التقرير التوثيقي كاملاً.' : 'Click "Generate Full Report" to produce the assessment document.'}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
