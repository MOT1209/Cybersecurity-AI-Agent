import React, { useState } from 'react';
import { apiFetch } from '../lib/api';
import { 
  BookOpen, 
  Search, 
  Sparkles, 
  AlertTriangle, 
  Code, 
  CheckCircle,
} from 'lucide-react';
import { OWASP_TOP_10, MITRE_TACTICS } from '../data/cyberData';
import ReactMarkdown from 'react-markdown';

interface KnowledgeBaseProps {
  language: 'ar' | 'en';
}

export const KnowledgeBase: React.FC<KnowledgeBaseProps> = ({ language }) => {
  const isAr = language === 'ar';
  const [activeSection, setActiveSection] = useState<'owasp' | 'mitre' | 'cve_ai'>('owasp');
  const [selectedOwasp, setSelectedOwasp] = useState<string>(OWASP_TOP_10[0].id);
  const [codeTab, setCodeTab] = useState<'vulnerable' | 'fixed'>('vulnerable');

  // MITRE state
  const [selectedTactic, setSelectedTactic] = useState<string>(MITRE_TACTICS[0].id);

  // CVE & Threat AI Search state
  const [cveQuery, setCveQuery] = useState<string>('CVE-2021-44228 (Log4j / Log4Shell)');
  const [cveLoading, setCveLoading] = useState<boolean>(false);
  const [cveResult, setCveResult] = useState<string | null>(null);

  const handleSearchThreat = async (queryToSearch?: string) => {
    const q = (queryToSearch || cveQuery).trim();
    if (!q || cveLoading) return;

    setCveLoading(true);
    setCveResult(null);

    try {
      const res = await apiFetch('/api/gemini/explain-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setCveResult(data.result);
    } catch (err: any) {
      console.error('Threat search error:', err);
      setCveResult(isAr ? 'حدث خطأ أثناء جلب تفاصيل الثغرة.' : 'Error fetching vulnerability details.');
    } finally {
      setCveLoading(false);
    }
  };

  const activeOwaspItem = OWASP_TOP_10.find((item) => item.id === selectedOwasp) || OWASP_TOP_10[0];
  const activeTacticItem = MITRE_TACTICS.find((t) => t.id === selectedTactic) || MITRE_TACTICS[0];

  const popularCVEs = [
    'CVE-2021-44228 (Log4j RCE)',
    'CVE-2017-0144 (EternalBlue SMB)',
    'CVE-2023-34362 (MOVEit Transfer SQLi)',
    'CVE-2022-22965 (Spring4Shell)',
    'CVE-2021-3156 (Baron Samedit Sudo PrivEsc)',
    'CVE-2024-3094 (XZ Utils Backdoor)',
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col gap-5">
      {/* Top Header & Switcher */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-slate-900/90 border border-slate-800 rounded-xl p-3.5">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-blue-950 border border-blue-800/60 text-blue-400">
            <BookOpen className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>{isAr ? 'قاعدة المعرفة والمعايير الأمنية' : 'Cybersecurity Frameworks & Threat Intel'}</span>
            </h2>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'استكشف أهم معايير الويب OWASP Top 10، مصفوفة هجمات MITRE ATT&CK، واستعلم عن أي ثغرة CVE بالذكاء الاصطناعي.'
                : 'Deep dive into OWASP Top 10, MITRE ATT&CK matrix, and live AI CVE threat intelligence.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveSection('owasp')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeSection === 'owasp' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            OWASP Top 10
          </button>
          <button
            onClick={() => setActiveSection('mitre')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeSection === 'mitre' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            MITRE ATT&CK
          </button>
          <button
            onClick={() => setActiveSection('cve_ai')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeSection === 'cve_ai' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {isAr ? 'مستكشف ثغرات CVE' : 'CVE Radar (AI)'}
          </button>
        </div>
      </div>

      {/* SECTION 1: OWASP Top 10 */}
      {activeSection === 'owasp' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* List of items */}
          <div className="lg:col-span-4 flex flex-col gap-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-1">
              {isAr ? 'تصنيفات OWASP Web Top 10:' : 'OWASP Categories:'}
            </span>
            {OWASP_TOP_10.map((item) => {
              const isSelected = item.id === selectedOwasp;
              return (
                <button
                  key={item.id}
                  onClick={() => setSelectedOwasp(item.id)}
                  className={`flex flex-col text-start p-3 rounded-xl border transition-all ${
                    isSelected
                      ? 'bg-slate-800 border-cyan-500/80 shadow-md shadow-cyan-950/40'
                      : 'bg-slate-900/60 border-slate-800/80 hover:bg-slate-800/60 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 w-full mb-1">
                    <span className="text-xs font-bold text-cyan-400 font-mono">{item.code}</span>
                    <span className="text-[10px] text-slate-500 font-mono">{item.cweList[0]}</span>
                  </div>
                  <span className="text-xs font-semibold text-slate-100 line-clamp-1">
                    {isAr ? item.titleAr : item.titleEn}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Details Card */}
          <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col gap-4">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
              <div>
                <span className="text-xs font-bold text-cyan-400 font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800">
                  {activeOwaspItem.code}
                </span>
                <h3 className="text-base font-bold text-slate-100 mt-2">
                  {isAr ? activeOwaspItem.titleAr : activeOwaspItem.titleEn}
                </h3>
              </div>

              <div className="flex flex-wrap gap-1">
                {activeOwaspItem.cweList.slice(0, 4).map((cwe, idx) => (
                  <span key={idx} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                    {cwe}
                  </span>
                ))}
              </div>
            </div>

            <div className="text-xs text-slate-300 leading-relaxed">
              <p className="font-semibold text-slate-200 mb-1">{isAr ? 'شرح الثغرة:' : 'Overview:'}</p>
              <p className="text-slate-400 leading-relaxed">{isAr ? activeOwaspItem.descriptionAr : activeOwaspItem.descriptionEn}</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="p-3 rounded-lg bg-slate-950 border border-rose-900/40 text-xs">
                <span className="font-semibold text-rose-400 mb-1 block flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>{isAr ? 'الأثر الأمني (Impact):' : 'Impact:'}</span>
                </span>
                <p className="text-slate-300 text-[11px] leading-relaxed">{activeOwaspItem.impact}</p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-emerald-900/40 text-xs">
                <span className="font-semibold text-emerald-400 mb-1 block flex items-center gap-1.5">
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>{isAr ? 'طرق الوقاية والحماية (Prevention):' : 'Prevention:'}</span>
                </span>
                <p className="text-slate-300 text-[11px] leading-relaxed">{activeOwaspItem.prevention}</p>
              </div>
            </div>

            {/* Code Samples Tab */}
            <div className="flex flex-col gap-2 mt-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Code className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{isAr ? 'مقارنة الكود (Vulnerable vs Secure Code):' : 'Code Pattern:'}</span>
                </span>
                <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-[11px]">
                  <button
                    onClick={() => setCodeTab('vulnerable')}
                    className={`px-2.5 py-1 rounded transition-colors ${
                      codeTab === 'vulnerable' ? 'bg-red-950 text-red-300 font-bold' : 'text-slate-400'
                    }`}
                  >
                    {isAr ? 'الكود المصاب' : 'Vulnerable'}
                  </button>
                  <button
                    onClick={() => setCodeTab('fixed')}
                    className={`px-2.5 py-1 rounded transition-colors ${
                      codeTab === 'fixed' ? 'bg-emerald-950 text-emerald-300 font-bold' : 'text-slate-400'
                    }`}
                  >
                    {isAr ? 'الكود الآمن' : 'Secured'}
                  </button>
                </div>
              </div>

              <pre
                className={`p-3.5 rounded-xl border font-mono text-xs overflow-x-auto leading-relaxed ${
                  codeTab === 'vulnerable'
                    ? 'bg-slate-950 border-red-900/40 text-red-300'
                    : 'bg-slate-950 border-emerald-900/40 text-emerald-300'
                }`}
              >
                <code>{codeTab === 'vulnerable' ? activeOwaspItem.exampleVulnerable : activeOwaspItem.exampleFixed}</code>
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 2: MITRE ATT&CK Matrix */}
      {activeSection === 'mitre' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-4 flex flex-col gap-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-1">
              {isAr ? 'تكتيكات هجمات MITRE ATT&CK:' : 'ATT&CK Tactics:'}
            </span>
            {MITRE_TACTICS.map((tactic) => {
              const isSelected = tactic.id === selectedTactic;
              return (
                <button
                  key={tactic.id}
                  onClick={() => setSelectedTactic(tactic.id)}
                  className={`flex flex-col text-start p-3 rounded-xl border transition-all ${
                    isSelected
                      ? 'bg-slate-800 border-cyan-500/80 shadow-md shadow-cyan-950/40'
                      : 'bg-slate-900/60 border-slate-800/80 hover:bg-slate-800/60 text-slate-300'
                  }`}
                >
                  <span className="text-[10px] font-mono text-cyan-400 font-bold">{tactic.id}</span>
                  <span className="text-xs font-bold text-slate-100 mt-0.5">
                    {isAr ? tactic.nameAr : tactic.nameEn}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col gap-4">
            <div>
              <span className="text-xs font-bold text-cyan-400 font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800">
                {activeTacticItem.id}
              </span>
              <h3 className="text-base font-bold text-slate-100 mt-2">
                {isAr ? activeTacticItem.nameAr : activeTacticItem.nameEn}
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                {isAr ? activeTacticItem.descriptionAr : activeTacticItem.descriptionEn}
              </p>
            </div>

            <div className="flex flex-col gap-3 mt-2">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                {isAr ? 'أبرز التقنيات وأساليب الكشف الدفاعي (Techniques & Detection):' : 'Techniques & Detection:'}
              </h4>
              {activeTacticItem.techniques.map((tech) => (
                <div key={tech.id} className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col gap-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-100">{tech.name}</span>
                    <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-900">
                      {tech.id}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{tech.description}</p>
                  <div className="mt-1 p-2 rounded bg-slate-900 border border-slate-800/80 text-[11px] text-slate-300">
                    <span className="font-semibold text-emerald-400">{isAr ? 'الكشف والرصد: ' : 'Detection: '}</span>
                    <span>{tech.detection}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SECTION 3: AI CVE & Threat Explainer */}
      {activeSection === 'cve_ai' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span>{isAr ? 'مستكشف ومحلل ثغرات CVE الذكي' : 'AI CVE Threat Intelligence Explainer'}</span>
            </h3>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'ابحث عن أي رقم CVE أو اسم ثغرة أو مفهوم أمني للحصول على تحليل تقني مفصل، سيناريو الاستغلال، وطرق الترقيع.'
                : 'Search any CVE identifier or threat keyword for in-depth AI technical breakdown and mitigation roadmap.'}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-500 absolute top-3 left-3" />
              <input
                type="text"
                value={cveQuery}
                onChange={(e) => setCveQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearchThreat()}
                placeholder={isAr ? 'اكتب معرف الثغرة مثل CVE-2021-44228...' : 'Enter CVE ID or threat name...'}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-700"
              />
            </div>
            <button
              onClick={() => handleSearchThreat()}
              disabled={!cveQuery.trim() || cveLoading}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-teal-500 text-slate-950 font-bold text-xs shadow-md shadow-cyan-950 disabled:opacity-50 flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{cveLoading ? (isAr ? 'جاري التحليل...' : 'Analyzing...') : (isAr ? 'تحليل الثغرة' : 'Analyze')}</span>
            </button>
          </div>

          {/* Preset CVE Pills */}
          <div className="flex items-center gap-1.5 overflow-x-auto py-1 no-scrollbar">
            <span className="text-[11px] text-slate-400 font-medium whitespace-nowrap">{isAr ? 'ثغرات شائعة:' : 'Popular:'}</span>
            {popularCVEs.map((item, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setCveQuery(item);
                  handleSearchThreat(item);
                }}
                className="flex-shrink-0 text-[11px] font-mono px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-800 text-slate-300 hover:text-cyan-300 transition-colors"
              >
                {item}
              </button>
            ))}
          </div>

          {/* CVE AI Results View */}
          {cveResult && (
            <div className="mt-3 p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 leading-relaxed max-h-[500px] overflow-y-auto">
              <div className="prose prose-invert max-w-none text-xs">
                <ReactMarkdown>{cveResult}</ReactMarkdown>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
