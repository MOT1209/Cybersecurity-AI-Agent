/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tool registry & health page (§31/§32).
 *
 * Every value here comes from GET /api/tools/health, which performs real
 * probes: is an adapter implemented, is the sandbox reachable, is the container
 * image actually present. Nothing on this page is a catalog claim — a tool is
 * never shown as usable unless the backend verified it.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../lib/api';
import {
  Wrench,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FlaskConical,
  ShieldAlert,
  PlugZap,
} from 'lucide-react';

interface ToolRegistryProps {
  language: 'ar' | 'en';
}

type ToolHealthState =
  | 'READY'
  | 'SIMULATED_ONLY'
  | 'NOT_INSTALLED'
  | 'NOT_IMPLEMENTED'
  | 'SANDBOX_UNAVAILABLE';

interface ToolHealth {
  toolId: string;
  name: string;
  adapterVersion: string | null;
  state: ToolHealthState;
  implemented: boolean;
  imagePresent: boolean | null;
  image?: string;
  sandboxAvailable: boolean;
  sandboxRequired: boolean;
  riskLevel: string;
  reason: string;
  checkedAt: string;
}

const STATE_STYLE: Record<
  ToolHealthState,
  { dot: string; chip: string; icon: React.ReactNode; labelAr: string; labelEn: string }
> = {
  READY: {
    dot: 'bg-emerald-400',
    chip: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60',
    icon: <CheckCircle2 className="w-3.5 h-3.5" />,
    labelAr: 'جاهزة',
    labelEn: 'Ready',
  },
  SIMULATED_ONLY: {
    dot: 'bg-amber-400',
    chip: 'bg-amber-950/80 text-amber-300 border-amber-700/60',
    icon: <FlaskConical className="w-3.5 h-3.5" />,
    labelAr: 'محاكاة فقط',
    labelEn: 'Simulated only',
  },
  NOT_INSTALLED: {
    dot: 'bg-sky-400',
    chip: 'bg-sky-950/80 text-sky-300 border-sky-700/60',
    icon: <PlugZap className="w-3.5 h-3.5" />,
    labelAr: 'الصورة غير موجودة',
    labelEn: 'Image not present',
  },
  NOT_IMPLEMENTED: {
    dot: 'bg-slate-500',
    chip: 'bg-slate-900 text-slate-400 border-slate-700',
    icon: <XCircle className="w-3.5 h-3.5" />,
    labelAr: 'غير مُنفَّذة',
    labelEn: 'Not implemented',
  },
  SANDBOX_UNAVAILABLE: {
    dot: 'bg-rose-400',
    chip: 'bg-rose-950/80 text-rose-300 border-rose-700/60',
    icon: <AlertTriangle className="w-3.5 h-3.5" />,
    labelAr: 'البيئة المعزولة غير متاحة',
    labelEn: 'Sandbox unavailable',
  },
};

const RISK_STYLE: Record<string, string> = {
  LOW: 'text-emerald-300 border-emerald-800/60 bg-emerald-950/50',
  MEDIUM: 'text-amber-300 border-amber-800/60 bg-amber-950/50',
  HIGH: 'text-orange-300 border-orange-800/60 bg-orange-950/50',
  CRITICAL: 'text-rose-300 border-rose-800/60 bg-rose-950/50',
};

export const ToolRegistry: React.FC<ToolRegistryProps> = ({ language }) => {
  const isAr = language === 'ar';
  const [tools, setTools] = useState<ToolHealth[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/tools/health');
      if (!res.ok) {
        setError(`HTTP ${res.status}`);
        return;
      }
      const data = await res.json();
      setTools(data.tools ?? []);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const ready = tools.filter((t) => t.state === 'READY').length;
  const implemented = tools.filter((t) => t.implemented).length;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      <div className="bg-slate-900/90 border border-cyan-500/20 rounded-2xl p-6 backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Wrench className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100">
                {isAr ? 'سجل الأدوات وحالتها الفعلية' : 'Tool Registry & Health'}
              </h2>
              <p className="text-sm text-slate-400 mt-1 max-w-2xl">
                {isAr
                  ? 'كل حالة هنا مُتحقَّق منها فعلياً: هل المحوّل مُنفَّذ، هل البيئة المعزولة متاحة، وهل صورة الحاوية موجودة. لا تُعرض أداة كجاهزة إلا إذا أثبتت الخلفية ذلك.'
                  : 'Every state here is verified: is an adapter implemented, is the sandbox reachable, is the container image present. No tool is shown as usable unless the backend proved it.'}
              </p>
            </div>
          </div>

          <button
            onClick={load}
            disabled={isLoading}
            className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition-colors flex items-center gap-2 shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : 'text-cyan-400'}`} />
            <span>{isAr ? 'إعادة الفحص' : 'Re-probe'}</span>
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mt-6 pt-5 border-t border-slate-800/80">
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">{isAr ? 'مُسجَّلة' : 'Registered'}</span>
            <span className="text-xl font-bold font-mono text-slate-200">{tools.length}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">
              {isAr ? 'لها محوّل مُنفَّذ' : 'Adapter implemented'}
            </span>
            <span className="text-xl font-bold font-mono text-cyan-300">{implemented}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">
              {isAr ? 'جاهزة للتنفيذ الآن' : 'Ready to run now'}
            </span>
            <span className="text-xl font-bold font-mono text-emerald-300">{ready}</span>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-rose-950/30 border border-rose-500/30 rounded-xl p-4 text-sm text-rose-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0" />
          <span>
            {isAr ? 'تعذّر جلب حالة الأدوات: ' : 'Could not load tool health: '}
            {error}
          </span>
        </div>
      )}

      {isLoading && tools.length === 0 && (
        <div className="text-center text-slate-500 py-12 text-sm">
          {isAr ? 'جاري فحص الأدوات...' : 'Probing tools...'}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {tools.map((t) => {
          const style = STATE_STYLE[t.state] ?? STATE_STYLE.NOT_IMPLEMENTED;
          return (
            <div
              key={t.toolId}
              className={`bg-slate-900/80 border rounded-xl p-4 space-y-3 ${
                t.implemented ? 'border-slate-800' : 'border-slate-800/60 opacity-70'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${style.dot}`} />
                    <h4 className="text-sm font-bold text-slate-100 truncate">{t.name}</h4>
                  </div>
                  <span className="text-[10px] font-mono text-cyan-400">@{t.toolId}</span>
                </div>
                <span
                  className={`shrink-0 text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${style.chip}`}
                >
                  {style.icon}
                  <span>{isAr ? style.labelAr : style.labelEn}</span>
                </span>
              </div>

              {/* The backend's own words for why it is in this state. */}
              <p className="text-xs text-slate-400 leading-relaxed">{t.reason}</p>

              <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 pt-2 border-t border-slate-800 text-[11px] font-mono">
                <dt className="text-slate-500">{isAr ? 'الخطورة' : 'Risk'}</dt>
                <dd>
                  <span
                    className={`px-1.5 py-0.5 rounded border ${
                      RISK_STYLE[t.riskLevel] ?? 'text-slate-400 border-slate-700 bg-slate-950'
                    }`}
                  >
                    {t.riskLevel}
                  </span>
                </dd>

                <dt className="text-slate-500">{isAr ? 'إصدار المحوّل' : 'Adapter'}</dt>
                <dd className={t.adapterVersion ? 'text-slate-300' : 'text-slate-600'}>
                  {t.adapterVersion ?? (isAr ? 'لا يوجد' : 'none')}
                </dd>

                <dt className="text-slate-500">{isAr ? 'يتطلب عزلاً' : 'Sandbox required'}</dt>
                <dd className="text-slate-300">{t.sandboxRequired ? 'yes' : 'no'}</dd>

                <dt className="text-slate-500">{isAr ? 'صورة الحاوية' : 'Image present'}</dt>
                <dd
                  className={
                    t.imagePresent === true
                      ? 'text-emerald-300'
                      : t.imagePresent === false
                        ? 'text-amber-300'
                        : 'text-slate-600'
                  }
                >
                  {/* null means "not checked", which is not the same as "no". */}
                  {t.imagePresent === null ? (isAr ? 'لم يُفحص' : 'not checked') : String(t.imagePresent)}
                </dd>
              </dl>

              {t.image && (
                <div className="text-[10px] font-mono text-slate-600 truncate" title={t.image}>
                  {t.image}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
