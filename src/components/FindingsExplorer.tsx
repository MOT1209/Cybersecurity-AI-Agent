/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Findings explorer (§18/§19).
 *
 * The point of this page is the distinction the platform enforces everywhere
 * else: a scanner result is a DETECTION, not a vulnerability. Severity is what
 * the tool claimed; verification status is what the platform will stand behind.
 * Confirmed findings are visually separated from everything else, and the
 * validator's rationale, false-positive risks and missing evidence are shown
 * rather than hidden behind a confident-looking severity badge.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../lib/api';
import {
  Bug,
  RefreshCw,
  ShieldCheck,
  HelpCircle,
  ScanSearch,
  FileWarning,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

interface FindingsExplorerProps {
  language: 'ar' | 'en';
}

type VerificationStatus = 'DETECTED' | 'ANALYZING' | 'CONFIRMED' | 'UNCONFIRMED' | 'FALSE_POSITIVE';

interface Evidence {
  source: string;
  observation: string;
  outputHash?: string;
  collectedAt: string;
}

interface Finding {
  id: string;
  projectId: string;
  traceId?: string;
  target: string;
  asset: string;
  discoveredByAgent: string;
  toolUsed: string;
  title: string;
  description: string;
  evidence: Evidence[];
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cwe: string[];
  owaspCategory?: string;
  impact: string;
  validation: {
    status: VerificationStatus;
    confidence: number;
    validatedByAgent?: string;
    rationale?: string;
    falsePositiveIndicators: string[];
    missingEvidence: string[];
  };
  createdAt: string;
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: 'text-rose-300 border-rose-700/60 bg-rose-950/60',
  HIGH: 'text-orange-300 border-orange-700/60 bg-orange-950/60',
  MEDIUM: 'text-amber-300 border-amber-700/60 bg-amber-950/60',
  LOW: 'text-sky-300 border-sky-700/60 bg-sky-950/60',
  INFO: 'text-slate-300 border-slate-700 bg-slate-900',
};

const STATUS_STYLE: Record<
  VerificationStatus,
  { chip: string; icon: React.ReactNode; labelAr: string; labelEn: string }
> = {
  CONFIRMED: {
    chip: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60',
    icon: <ShieldCheck className="w-3.5 h-3.5" />,
    labelAr: 'مؤكَّدة',
    labelEn: 'Confirmed',
  },
  DETECTED: {
    chip: 'bg-slate-900 text-slate-400 border-slate-700',
    icon: <ScanSearch className="w-3.5 h-3.5" />,
    labelAr: 'رصد فقط — لم يُتحقَّق',
    labelEn: 'Detected — not validated',
  },
  ANALYZING: {
    chip: 'bg-cyan-950/80 text-cyan-300 border-cyan-700/60',
    icon: <RefreshCw className="w-3.5 h-3.5" />,
    labelAr: 'قيد التحليل',
    labelEn: 'Analyzing',
  },
  UNCONFIRMED: {
    chip: 'bg-amber-950/80 text-amber-300 border-amber-700/60',
    icon: <HelpCircle className="w-3.5 h-3.5" />,
    labelAr: 'غير مؤكَّدة',
    labelEn: 'Unconfirmed',
  },
  FALSE_POSITIVE: {
    chip: 'bg-slate-900 text-slate-500 border-slate-700',
    icon: <FileWarning className="w-3.5 h-3.5" />,
    labelAr: 'إيجابية كاذبة',
    labelEn: 'False positive',
  },
};

export const FindingsExplorer: React.FC<FindingsExplorerProps> = ({ language }) => {
  const isAr = language === 'ar';
  const [findings, setFindings] = useState<Finding[]>([]);
  const [counts, setCounts] = useState({ total: 0, confirmed: 0, detected: 0, unconfirmed: 0 });
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const qs = statusFilter === 'ALL' ? '' : `?status=${encodeURIComponent(statusFilter)}`;
      const res = await apiFetch(`/api/findings${qs}`);
      if (res.ok) {
        const data = await res.json();
        setFindings(data.findings ?? []);
        setCounts(data.counts ?? { total: 0, confirmed: 0, detected: 0, unconfirmed: 0 });
      }
    } catch (e) {
      console.warn('Failed to load findings', e);
    } finally {
      setIsLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      <div className="bg-slate-900/90 border border-rose-500/20 rounded-2xl p-6 backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-rose-950/80 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <Bug className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100">
                {isAr ? 'النتائج والتحقق منها' : 'Findings & Validation'}
              </h2>
              <p className="text-sm text-slate-400 mt-1 max-w-2xl">
                {isAr
                  ? 'نتيجة الفاحص ليست ثغرة. تدخل كل نتيجة بحالة "رصد" وثقة صفر، ولا تصل إلى "مؤكَّدة" إلا عبر وكيل التحقق المبني على الأدلة.'
                  : 'A scanner result is not a vulnerability. Every finding enters as DETECTED with confidence 0 and only reaches CONFIRMED through evidence-based validation.'}
              </p>
            </div>
          </div>

          <button
            onClick={load}
            disabled={isLoading}
            className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition-colors flex items-center gap-2 shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : 'text-cyan-400'}`} />
            <span>{isAr ? 'تحديث' : 'Refresh'}</span>
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-slate-800/80">
          {([
            ['total', isAr ? 'الإجمالي' : 'Total', 'text-slate-200'],
            ['confirmed', isAr ? 'مؤكَّدة' : 'Confirmed', 'text-emerald-300'],
            ['detected', isAr ? 'رصد فقط' : 'Detected only', 'text-slate-400'],
            ['unconfirmed', isAr ? 'غير مؤكَّدة' : 'Unconfirmed', 'text-amber-300'],
          ] as const).map(([key, label, color]) => (
            <div key={key} className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
              <span className="text-xs text-slate-400 block mb-1">{label}</span>
              <span className={`text-xl font-bold font-mono ${color}`}>{counts[key]}</span>
            </div>
          ))}
        </div>

        <div className="flex flex-wrap gap-2 mt-4">
          {['ALL', 'CONFIRMED', 'DETECTED', 'UNCONFIRMED', 'FALSE_POSITIVE'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 text-[11px] font-mono rounded border transition-colors ${
                statusFilter === s
                  ? 'bg-cyan-950/80 text-cyan-300 border-cyan-700'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {!isLoading && findings.length === 0 && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 text-sm">
          {isAr
            ? 'لا توجد نتائج مُسجَّلة. شغّل مهمة من لوحة المنسّق لتوليد نتائج حقيقية من فحص فعلي.'
            : 'No findings recorded. Run a mission from the orchestrator to produce findings from a real scan.'}
        </div>
      )}

      <div className="space-y-3">
        {findings.map((f) => {
          const st = STATUS_STYLE[f.validation.status] ?? STATUS_STYLE.DETECTED;
          const isOpen = expanded === f.id;
          const isConfirmed = f.validation.status === 'CONFIRMED';
          return (
            <div
              key={f.id}
              className={`bg-slate-900/80 border rounded-xl overflow-hidden transition-colors ${
                isConfirmed ? 'border-emerald-800/60' : 'border-slate-800'
              }`}
            >
              <button
                onClick={() => setExpanded(isOpen ? null : f.id)}
                className="w-full text-start p-4 flex items-start gap-3 hover:bg-slate-900"
              >
                {isOpen ? (
                  <ChevronDown className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
                )}

                <div className="flex-1 min-w-0 space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                        SEVERITY_STYLE[f.severity] ?? SEVERITY_STYLE.INFO
                      }`}
                      title={
                        isAr
                          ? 'الخطورة كما ادّعتها الأداة — ليست حكماً من المنصة'
                          : 'Severity as claimed by the tool — not the platform verdict'
                      }
                    >
                      {f.severity}
                    </span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border flex items-center gap-1 ${st.chip}`}>
                      {st.icon}
                      <span>{isAr ? st.labelAr : st.labelEn}</span>
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {isAr ? 'ثقة' : 'confidence'} {f.validation.confidence}%
                    </span>
                  </div>

                  <h4 className="text-sm font-semibold text-slate-100 truncate">{f.title}</h4>
                  <div className="text-[11px] font-mono text-slate-500 truncate">
                    {f.asset} · {f.toolUsed} · @{f.discoveredByAgent}
                  </div>
                </div>
              </button>

              {isOpen && (
                <div className="px-4 pb-4 space-y-3 text-xs border-t border-slate-800/80 pt-3">
                  <p className="text-slate-300 leading-relaxed">{f.description}</p>
                  <p className="text-slate-400">
                    <strong className="text-slate-500">{isAr ? 'الأثر: ' : 'Impact: '}</strong>
                    {f.impact}
                  </p>

                  <div>
                    <div className="text-[11px] font-mono text-slate-500 mb-1">
                      {isAr ? 'الأدلة المرصودة' : 'Recorded evidence'}
                    </div>
                    <div className="space-y-1">
                      {f.evidence.map((e, i) => (
                        <div key={i} className="bg-slate-950/70 border border-slate-800 rounded p-2 font-mono text-[11px]">
                          <div className="text-slate-300">{e.observation}</div>
                          <div className="text-slate-600 mt-1 truncate">
                            {e.source}
                            {/* An unhashed observation cannot be tied to a run, which caps confidence. */}
                            {e.outputHash
                              ? ` · ${e.outputHash}`
                              : ` · ${isAr ? 'بلا بصمة مخرجات' : 'no output hash'}`}
                          </div>
                        </div>
                      ))}
                      {f.evidence.length === 0 && (
                        <div className="text-slate-600">{isAr ? 'لا أدلة' : 'none'}</div>
                      )}
                    </div>
                  </div>

                  {f.validation.rationale && (
                    <p className="text-slate-400">
                      <strong className="text-slate-500">{isAr ? 'حكم المُحقِّق: ' : 'Validator rationale: '}</strong>
                      {f.validation.rationale}
                    </p>
                  )}

                  {f.validation.falsePositiveIndicators.length > 0 && (
                    <div className="bg-amber-950/20 border border-amber-800/40 rounded p-2">
                      <div className="text-[11px] font-mono text-amber-300 mb-1">
                        {isAr ? 'مؤشرات احتمال الإيجابية الكاذبة' : 'False-positive indicators'}
                      </div>
                      <ul className="list-disc list-inside space-y-0.5 text-amber-200/80 text-[11px]">
                        {f.validation.falsePositiveIndicators.map((x, i) => (
                          <li key={i}>{x}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {f.validation.missingEvidence.length > 0 && (
                    <div className="bg-slate-950/70 border border-slate-800 rounded p-2">
                      <div className="text-[11px] font-mono text-slate-400 mb-1">
                        {isAr ? 'الأدلة الناقصة للتأكيد' : 'Evidence still needed to confirm'}
                      </div>
                      <ul className="list-disc list-inside space-y-0.5 text-slate-400 text-[11px]">
                        {f.validation.missingEvidence.map((x, i) => (
                          <li key={i}>{x}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="flex flex-wrap gap-3 text-[10px] font-mono text-slate-600 pt-1">
                    <span>{f.id}</span>
                    {f.cwe.map((c) => (
                      <span key={c}>{c}</span>
                    ))}
                    {f.owaspCategory && <span>{f.owaspCategory}</span>}
                    {f.traceId && <span>trace {f.traceId}</span>}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
