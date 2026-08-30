import React, { useState } from 'react';
import { apiFetch } from '../lib/api';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Play, 
  Copy, 
  Check, 
  Sparkles, 
  AlertTriangle, 
  FileCode, 
  CheckCircle2, 
  RefreshCw,
} from 'lucide-react';
import { CODE_AUDIT_SAMPLES } from '../data/cyberData';
import { AuditResult } from '../types';
import { useCopy } from '../lib/useCopy';

interface CodeAuditorProps {
  language: 'ar' | 'en';
}

export const CodeAuditor: React.FC<CodeAuditorProps> = ({ language }) => {
  const isAr = language === 'ar';
  const [selectedSample, setSelectedSample] = useState<string>('sqli-flask');
  const [code, setCode] = useState<string>(CODE_AUDIT_SAMPLES[0].code);
  const [codeLang, setCodeLang] = useState<string>('python');
  const [loading, setLoading] = useState<boolean>(false);
  const [auditResult, setAuditResult] = useState<AuditResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const { copy, isCopied } = useCopy();
  const [activeTab, setActiveTab] = useState<'overview' | 'vulns' | 'patch' | 'practices'>('overview');

  const handleSampleChange = (id: string) => {
    setSelectedSample(id);
    const sample = CODE_AUDIT_SAMPLES.find((s) => s.id === id);
    if (sample) {
      setCode(sample.code);
      setCodeLang(sample.language);
      setAuditResult(null);
      setErrorMsg(null);
    }
  };

  const handleRunAudit = async () => {
    if (!code.trim() || loading) return;

    setLoading(true);
    setErrorMsg(null);

    try {
      const res = await apiFetch('/api/gemini/audit-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code,
          language: codeLang,
          context: 'Full Application Security Audit & SAST review',
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${res.status}`);
      }

      const data: AuditResult = await res.json();
      setAuditResult(data);
      setActiveTab('vulns');
    } catch (err: any) {
      console.error('Audit failed:', err);
      setErrorMsg(err?.message || (isAr ? 'فشل إجراء التدقيق الأمني' : 'Security audit failed'));
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-400 border-red-800/80';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-400 border-orange-800/80';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-400 border-amber-800/80';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-400 border-blue-800/80';
      default:
        return 'bg-emerald-950/80 text-emerald-400 border-emerald-800/80';
    }
  };

  const getCVSSColor = (score: number) => {
    if (score >= 9.0) return 'text-red-500 stroke-red-500';
    if (score >= 7.0) return 'text-orange-500 stroke-orange-500';
    if (score >= 4.0) return 'text-amber-500 stroke-amber-500';
    if (score > 0) return 'text-blue-500 stroke-blue-500';
    return 'text-emerald-500 stroke-emerald-500';
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col gap-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-xl p-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            <span>{isAr ? 'فاحص ومراجع أمان الأكواد البرمجية (SAST Engine)' : 'Static Code Security Auditor (SAST)'}</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {isAr
              ? 'قم باختبار عينات كود مصابة بثغرات شائعة، أو ألصق كودك الخاص لاكتشاف ثغرات OWASP وتقديم كود الترقيع الآمن.'
              : 'Test vulnerable sample code or paste your own to detect OWASP flaws, calculate CVSS, and generate secure patches.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Sample Picker */}
          <div className="flex items-center gap-1.5 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5">
            <span className="text-xs text-slate-400 font-medium">{isAr ? 'نماذج جاهزة:' : 'Samples:'}</span>
            <select
              id="sample-code-select"
              value={selectedSample}
              onChange={(e) => handleSampleChange(e.target.value)}
              className="bg-transparent text-xs text-cyan-300 font-semibold focus:outline-none cursor-pointer"
            >
              {CODE_AUDIT_SAMPLES.map((s) => (
                <option key={s.id} value={s.id} className="bg-slate-900 text-slate-200">
                  {s.name}
                </option>
              ))}
            </select>
          </div>

          {/* Language Selector */}
          <select
            id="code-lang-select"
            value={codeLang}
            onChange={(e) => setCodeLang(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg px-2.5 py-2 focus:outline-none"
          >
            <option value="python">Python</option>
            <option value="javascript">JavaScript (Node.js)</option>
            <option value="typescript">TypeScript</option>
            <option value="php">PHP</option>
            <option value="go">Go (Golang)</option>
            <option value="java">Java</option>
            <option value="c">C / C++</option>
            <option value="sql">SQL Query</option>
            <option value="dockerfile">Dockerfile</option>
            <option value="nginx">Nginx Config</option>
          </select>

          {/* Scan Button */}
          <button
            id="run-audit-btn"
            onClick={handleRunAudit}
            disabled={loading || !code.trim()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-teal-500 hover:from-cyan-400 hover:to-teal-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-950 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {loading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>{isAr ? 'جاري الفحص المعمق...' : 'Auditing Code...'}</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-slate-950" />
                <span>{isAr ? 'بدء الفحص الأمني (AI Scan)' : 'Run AI Security Audit'}</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Main Grid: Code Editor on Left, Audit Results on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Code Input Box */}
        <div className="lg:col-span-6 flex flex-col bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-md">
          <div className="flex items-center justify-between px-4 py-2.5 bg-slate-950/80 border-b border-slate-800 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span>{isAr ? 'محرر الكود المستهدف للفحص' : 'Target Code Under Inspection'}</span>
            </div>
            <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 uppercase text-[10px]">
              {codeLang}
            </span>
          </div>

          <div className="relative flex-1 min-h-[380px]">
            <textarea
              id="audit-code-input"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder={isAr ? 'الصق كود التطبيق أو ملف التكوين هنا...' : 'Paste your application code or config here...'}
              className="w-full h-full min-h-[380px] p-4 bg-slate-950/50 text-slate-200 font-mono text-xs leading-relaxed focus:outline-none resize-none selection:bg-cyan-500/20"
              spellCheck={false}
            />
          </div>
        </div>

        {/* Audit Results Panel */}
        <div className="lg:col-span-6 flex flex-col bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-md">
          {/* Results Tabs Header */}
          <div className="flex items-center justify-between px-3 py-2 bg-slate-950/80 border-b border-slate-800">
            <div className="flex items-center gap-1 overflow-x-auto no-scrollbar">
              <button
                onClick={() => setActiveTab('overview')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  activeTab === 'overview' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {isAr ? 'الملخص والمخاطر' : 'Overview'}
              </button>
              <button
                onClick={() => setActiveTab('vulns')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
                  activeTab === 'vulns' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>{isAr ? 'الثغرات المكتشفة' : 'Vulnerabilities'}</span>
                {auditResult?.vulnerabilities && (
                  <span className="w-4 h-4 rounded-full bg-red-950 text-red-400 text-[10px] flex items-center justify-center font-mono">
                    {auditResult.vulnerabilities.length}
                  </span>
                )}
              </button>
              <button
                onClick={() => setActiveTab('patch')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  activeTab === 'patch' ? 'bg-slate-800 text-emerald-300' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {isAr ? 'الكود الآمن (Patch)' : 'Secure Code'}
              </button>
              <button
                onClick={() => setActiveTab('practices')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  activeTab === 'practices' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {isAr ? 'أفضل الممارسات' : 'Best Practices'}
              </button>
            </div>
          </div>

          {/* Results Content Area */}
          <div className="flex-1 p-4 overflow-y-auto max-h-[480px]">
            {loading && (
              <div className="h-full flex flex-col items-center justify-center py-12 text-center">
                <div className="w-12 h-12 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin mb-3" />
                <h4 className="text-sm font-semibold text-slate-200 mb-1">
                  {isAr ? 'جاري الفحص والتحليل الثابت للكود (SAST)...' : 'Performing Deep SAST Code Inspection...'}
                </h4>
                <p className="text-xs text-slate-400 max-w-xs">
                  {isAr
                    ? 'مطابقة الأنماط مع CWE و OWASP Top 10 وحساب درجة خطورة CVSS وتوليد الكود الآمن.'
                    : 'Matching CWE/OWASP patterns, evaluating CVSS score, and generating hardened patch.'}
                </p>
              </div>
            )}

            {errorMsg && (
              <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 text-rose-400" />
                <span>{errorMsg}</span>
              </div>
            )}

            {!loading && !auditResult && !errorMsg && (
              <div className="h-full flex flex-col items-center justify-center py-12 text-center text-slate-400">
                <ShieldCheck className="w-12 h-12 text-slate-700 mb-2" />
                <p className="text-sm font-medium text-slate-300">
                  {isAr ? 'لم يتم إجراء فحص بعد' : 'No audit run yet'}
                </p>
                <p className="text-xs text-slate-500 mt-1 max-w-xs">
                  {isAr
                    ? 'اختر نموذجاً أو الصق الكود ثم اضغط على زر بدء الفحص الأمني.'
                    : 'Select a sample or paste code, then click Run AI Security Audit.'}
                </p>
              </div>
            )}

            {auditResult && !loading && (
              <>
                {/* Tab: Overview */}
                {activeTab === 'overview' && (
                  <div className="flex flex-col gap-4">
                    {/* Top Stats Banner */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col">
                        <span className="text-[10px] text-slate-400 font-medium">{isAr ? 'مستوى الخطورة' : 'Overall Risk'}</span>
                        <span className={`text-sm font-bold mt-1 px-2 py-0.5 rounded border inline-block w-fit ${getSeverityBadge(auditResult.overallRisk)}`}>
                          {auditResult.overallRisk}
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col">
                        <span className="text-[10px] text-slate-400 font-medium">{isAr ? 'درجة CVSS v3.1' : 'CVSS Score'}</span>
                        <span className={`text-xl font-bold font-mono mt-0.5 ${getCVSSColor(auditResult.cvssScore)}`}>
                          {auditResult.cvssScore.toFixed(1)} / 10
                        </span>
                      </div>

                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col col-span-2 sm:col-span-1">
                        <span className="text-[10px] text-slate-400 font-medium">{isAr ? 'عدد الثغرات' : 'Flaws Found'}</span>
                        <span className="text-xl font-bold font-mono text-cyan-400 mt-0.5">
                          {auditResult.vulnerabilities.length}
                        </span>
                      </div>
                    </div>

                    {/* Summary Card */}
                    <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
                      <h4 className="text-xs font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                        <span>{isAr ? 'الملخص التنفيذي للفحص' : 'Executive Audit Summary'}</span>
                      </h4>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {auditResult.summary}
                      </p>
                    </div>
                  </div>
                )}

                {/* Tab: Vulnerabilities */}
                {activeTab === 'vulns' && (
                  <div className="flex flex-col gap-3">
                    {auditResult.vulnerabilities.map((v, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 rounded-xl bg-slate-950 border border-slate-800/90 flex flex-col gap-2 hover:border-slate-700 transition-colors"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <h4 className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                            <span>{v.title}</span>
                          </h4>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getSeverityBadge(v.severity)}`}>
                            {v.severity}
                          </span>
                        </div>

                        <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono text-slate-400">
                          {v.cwe && <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">{v.cwe}</span>}
                          {v.owasp && <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-amber-300">{v.owasp}</span>}
                          {v.lines && <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">{isAr ? `الأسطر: ${v.lines}` : `Lines: ${v.lines}`}</span>}
                        </div>

                        <div className="text-xs text-slate-300 mt-1">
                          <p className="font-medium text-slate-200 mb-0.5">{isAr ? 'الشرح الفني:' : 'Description:'}</p>
                          <p className="text-slate-400 leading-relaxed text-[11px]">{v.description}</p>
                        </div>

                        {v.impact && (
                          <div className="text-xs text-slate-300">
                            <p className="font-medium text-rose-300 mb-0.5">{isAr ? 'الأثر الأمني المحتمل:' : 'Impact:'}</p>
                            <p className="text-slate-400 leading-relaxed text-[11px]">{v.impact}</p>
                          </div>
                        )}

                        <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-xs">
                          <p className="font-medium text-emerald-400 mb-0.5">{isAr ? 'خطوات الإصلاح والترقيع:' : 'Remediation:'}</p>
                          <p className="text-slate-300 text-[11px] leading-relaxed">{v.remediation}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Tab: Secure Patch */}
                {activeTab === 'patch' && (
                  <div className="flex flex-col gap-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-slate-300 font-medium flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        <span>{isAr ? 'الكود المرقّع والآمن (Secure Fixed Code):' : 'Hardened & Remediated Code:'}</span>
                      </span>
                      <button
                        onClick={() => {
                          void copy(auditResult.securedCode, 'patch');
                        }}
                        className="flex items-center gap-1 text-xs text-slate-300 hover:text-emerald-400 px-2 py-1 rounded bg-slate-950 border border-slate-800 hover:border-emerald-800/80 transition-colors"
                      >
                        {isCopied('patch') ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{isCopied('patch') ? (isAr ? 'تم النسخ' : 'Copied') : (isAr ? 'نسخ الكود' : 'Copy')}</span>
                      </button>
                    </div>

                    <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 overflow-x-auto leading-relaxed max-h-[380px]">
                      <code>{auditResult.securedCode}</code>
                    </pre>
                  </div>
                )}

                {/* Tab: Best Practices */}
                {activeTab === 'practices' && (
                  <div className="flex flex-col gap-2">
                    <h4 className="text-xs font-semibold text-slate-200 mb-1">
                      {isAr ? 'توصيات التعزيز الأمني (Hardening Recommendations):' : 'Hardening Recommendations:'}
                    </h4>
                    {auditResult.bestPractices.map((bp, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 flex items-start gap-2 text-xs text-slate-300">
                        <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                        <span className="leading-relaxed">{bp}</span>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
