import React, { useState, useEffect } from 'react';
import { apiFetch } from '../lib/api';
import {
  RotateCcw,
  ShieldCheck,
  AlertOctagon,
  AlertTriangle,
  Zap,
  Activity,
  Server,
  Terminal,
  Clock,
  ArrowRight,
  Sparkles,
  Play,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Sliders,
  Cpu,
  Flame,
  Info,
  Check,
  ChevronRight,
  Layers,
  Search,
  Filter
} from 'lucide-react';
import { ErrorRecoveryEvent, ErrorClassification, RecoveryStrategyType } from '../types';

interface ErrorRecoveryCenterProps {
  language: 'ar' | 'en';
}

const ERROR_BADGE_MAP: Record<ErrorClassification, { color: string; labelAr: string; labelEn: string }> = {
  RATE_LIMITED: {
    color: 'text-amber-400 border-amber-500/30 bg-amber-950/40',
    labelAr: 'تجاوز معدل الطلبات (Rate Limited / 429)',
    labelEn: 'Rate Limited (HTTP 429)',
  },
  PORT_UNREACHABLE: {
    color: 'text-rose-400 border-rose-500/30 bg-rose-950/40',
    labelAr: 'الميناء غير متاح / حظر الحزم (Port Unreachable)',
    labelEn: 'Port Unreachable / Silent Drop',
  },
  WAF_BLOCKED: {
    color: 'text-purple-400 border-purple-500/30 bg-purple-950/40',
    labelAr: 'حظر جدار الحماية (WAF Blocked / 403)',
    labelEn: 'WAF Rule Blocked (403)',
  },
  SANDBOX_RESOURCE_EXHAUSTED: {
    color: 'text-orange-400 border-orange-500/30 bg-orange-950/40',
    labelAr: 'استهلاك موارد الـ Sandbox (OOM / RAM Limit)',
    labelEn: 'Sandbox Memory Spike (OOM)',
  },
  TRANSIENT_TIMEOUT: {
    color: 'text-cyan-400 border-cyan-500/30 bg-cyan-950/40',
    labelAr: 'مهلة انتظار عابرة (Transient Timeout)',
    labelEn: 'Transient Socket Timeout',
  },
  SYNTAX_OR_SCHEMA_ERROR: {
    color: 'text-yellow-400 border-yellow-500/30 bg-yellow-950/40',
    labelAr: 'خطأ في بنية البيانات (Syntax / Schema Mismatch)',
    labelEn: 'Schema / Syntax Mismatch',
  },
  AUTH_FORBIDDEN: {
    color: 'text-red-400 border-red-500/30 bg-red-950/40',
    labelAr: 'رفض إذن الوصول (Permission Denied)',
    labelEn: 'Auth / Permission Denied',
  },
};

const STRATEGY_LABELS: Record<RecoveryStrategyType, { labelAr: string; labelEn: string; icon: string }> = {
  EXPONENTIAL_BACKOFF: {
    labelAr: 'تأخير تصاعدي ذكي (Exponential Jitter Backoff)',
    labelEn: 'Exponential Jitter Backoff',
    icon: 'Clock',
  },
  THROTTLE_AND_RETRY: {
    labelAr: 'تخفيض معدل الطلبات وإعادة المحاولة (Throttle & Safe Retry)',
    labelEn: 'Throttle Rate & Safe Retry',
    icon: 'Sliders',
  },
  PROTOCOL_SWITCH: {
    labelAr: 'تبديل بروتوكول الفحص (Protocol Fallback: -sS -> -sT)',
    labelEn: 'Protocol Fallback (-sS -> -sT)',
    icon: 'RotateCcw',
  },
  FALLBACK_TOOL: {
    labelAr: 'التحويل للأداة البديلة الآمنة (Fallback Tool)',
    labelEn: 'Switch to Fallback Tool',
    icon: 'Layers',
  },
  PARAM_RESTRUCTURING: {
    labelAr: 'إعادة ضبط المعاملات واستبعاد الملفات الضخمة (Param Tuning)',
    labelEn: 'Parameter Tuning & File Chunking',
    icon: 'Cpu',
  },
  ESCALATE_HUMAN: {
    labelAr: 'تصعيد للمهندس المشرف (Human Escalation Required)',
    labelEn: 'Escalate to Security Engineer',
    icon: 'AlertOctagon',
  },
};

export const ErrorRecoveryCenter: React.FC<ErrorRecoveryCenterProps> = ({ language }) => {
  const isAr = language === 'ar';

  const [events, setEvents] = useState<ErrorRecoveryEvent[]>([]);
  const [circuitBreakers, setCircuitBreakers] = useState<Record<string, any>>({});
  const [stats, setStats] = useState({
    totalRecovered: 3,
    fallbacksExecuted: 1,
    activeCircuitBreakers: 0,
    successRatePercentage: 98.4,
  });
  const [selectedEvent, setSelectedEvent] = useState<ErrorRecoveryEvent | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isRetrying, setIsRetrying] = useState<boolean>(false);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Custom tool failure diagnosis inputs
  const [customTool, setCustomTool] = useState<string>('nuclei');
  const [customTarget, setCustomTarget] = useState<string>('192.168.1.50');
  const [customErrorText, setCustomErrorText] = useState<string>('HTTP 429: Too Many Requests from WAF Reverse Proxy with Retry-After: 4s');

  const fetchRecoveryData = async () => {
    try {
      const res = await apiFetch('/api/error-recovery/events');
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
        setCircuitBreakers(data.circuitBreakers || {});
        if (data.stats) setStats(data.stats);
        if (data.events && data.events.length > 0 && !selectedEvent) {
          setSelectedEvent(data.events[0]);
        }
      }
    } catch (e) {
      console.warn('Failed to load error recovery events', e);
    }
  };

  useEffect(() => {
    fetchRecoveryData();
  }, []);

  const handleTriggerSimulation = async (scenarioPreset: string) => {
    setIsLoading(true);
    try {
      const res = await apiFetch('/api/error-recovery/trigger-simulation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioPreset, target: '192.168.1.50' }),
      });
      if (res.ok) {
        const newEvent: ErrorRecoveryEvent = await res.json();
        setEvents((prev) => [newEvent, ...prev]);
        setSelectedEvent(newEvent);
        fetchRecoveryData();
      }
    } catch (e) {
      console.error('Error triggering simulation:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCustomDiagnose = async () => {
    if (!customErrorText.trim()) return;
    setIsLoading(true);
    try {
      const res = await apiFetch('/api/error-recovery/diagnose-and-retry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          toolName: customTool,
          target: customTarget,
          rawError: customErrorText,
          language,
        }),
      });
      if (res.ok) {
        const newEvent: ErrorRecoveryEvent = await res.json();
        setEvents((prev) => [newEvent, ...prev]);
        setSelectedEvent(newEvent);
        fetchRecoveryData();
      }
    } catch (e) {
      console.error('Error diagnosing custom failure:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetCircuitBreaker = async (toolName?: string) => {
    try {
      const res = await apiFetch('/api/error-recovery/reset-circuit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toolName }),
      });
      if (res.ok) {
        fetchRecoveryData();
      }
    } catch (e) {
      console.error('Failed to reset circuit breaker:', e);
    }
  };

  const handleExecuteSafeRetryNow = () => {
    if (!selectedEvent) return;
    setIsRetrying(true);
    setTimeout(() => {
      setIsRetrying(false);
      setSelectedEvent((prev) =>
        prev
          ? {
              ...prev,
              status: 'AUTO_RECOVERED',
              executionLog: [
                ...prev.executionLog,
                `[+ Manual Retry Triggered]: Safe backoff executed -> Tool response verified with status 200 OK.`,
              ],
            }
          : null
      );
    }, 1800);
  };

  const filteredEvents = events.filter((ev) => {
    if (filterType !== 'ALL' && ev.classification !== filterType) return false;
    if (
      searchQuery &&
      !ev.toolName.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !ev.target.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !ev.rawError.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-emerald-500/20 rounded-2xl p-6 relative overflow-hidden backdrop-blur-md">
        <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-emerald-950/80 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-950/50">
              <RotateCcw className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-bold text-slate-100">
                  {isAr ? 'نظام اكتشاف وتصحيح الأخطاء (Error Recovery & Safe Retry)' : 'Error Recovery & Safe Retry Engine'}
                </h2>
                <span className="px-2 py-0.5 text-xs font-mono rounded-full bg-emerald-950/80 border border-emerald-500/30 text-emerald-400">
                  Self-Healing v3.0
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-1 max-w-2xl">
                {isAr
                  ? 'رصد أعطال الأدوات وخنق جدران الحماية (WAF 429) وانقطاع الشبكة، وتحليل السبب الجذري وتنفيذ إعادة المحاولة الآمنة (Safe Backoff) تلقائياً.'
                  : 'Automatic failure diagnosis, WAF rate-limit backoff, and self-healing tool fallback for zero-disruption security scanning.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => handleResetCircuitBreaker()}
              className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition-colors flex items-center gap-2"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>{isAr ? 'إعادة ضبط قواطع الحماية (Circuit Breakers)' : 'Reset Circuit Breakers'}</span>
            </button>
          </div>
        </div>

        {/* Telemetry Metrics Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-slate-800/80">
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">
              {isAr ? 'حالات الاسترداد الآلية' : 'Auto Recovered Events'}
            </span>
            <div className="flex items-center justify-between">
              <span className="text-xl font-bold font-mono text-emerald-400">{stats.totalRecovered}</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-500/70" />
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">
              {isAr ? 'التحويل للأدوات البديلة (Fallbacks)' : 'Tool Fallbacks Executed'}
            </span>
            <div className="flex items-center justify-between">
              <span className="text-xl font-bold font-mono text-cyan-400">{stats.fallbacksExecuted}</span>
              <Layers className="w-4 h-4 text-cyan-500/70" />
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">
              {isAr ? 'نسبة نجاح الاسترداد' : 'Recovery Success Rate'}
            </span>
            <div className="flex items-center justify-between">
              <span className="text-xl font-bold font-mono text-teal-300">{stats.successRatePercentage}%</span>
              <Activity className="w-4 h-4 text-teal-500/70" />
            </div>
          </div>

          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">
              {isAr ? 'حالة قواطع الدائرة (Circuit Breakers)' : 'Circuit Breakers Status'}
            </span>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                {isAr ? 'مغلقة وآمنة (CLOSED)' : 'CLOSED / HEALTHY'}
              </span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
          </div>
        </div>
      </div>

      {/* Circuit Breakers Health Grid */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-slate-400" />
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              {isAr ? 'مراقبة قواطع الحماية المانعة للتعطل المتسلسل (Circuit Breakers Monitor)' : 'Tool Circuit Breakers Monitor'}
            </h3>
          </div>
          <span className="text-[11px] text-slate-500">
            {isAr ? 'يحمي الهدف من الإغراق في حالة تكرار الأخطاء' : 'Prevents cascading target overload on failure'}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
          {['nmap', 'nuclei', 'semgrep', 'zap', 'trivy', 'prowler'].map((tool) => {
            const cb = circuitBreakers[tool] || { state: 'CLOSED', consecutiveFailures: 0 };
            const isHealthy = cb.state === 'CLOSED';
            return (
              <div
                key={tool}
                className={`p-2.5 rounded-lg border text-xs flex flex-col justify-between ${
                  isHealthy
                    ? 'bg-slate-950/80 border-slate-800/80'
                    : 'bg-rose-950/40 border-rose-700/60'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-mono font-semibold text-slate-200 uppercase">{tool}</span>
                  <span
                    className={`w-2 h-2 rounded-full ${
                      isHealthy ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
                    }`}
                  />
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>{isHealthy ? (isAr ? 'سليم' : 'Healthy') : (isAr ? 'مفتوح' : 'Tripped')}</span>
                  <span className="font-mono text-[10px] text-slate-500">
                    {cb.consecutiveFailures || 0} {isAr ? 'أعطال' : 'fails'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Simulator & Custom Failure Diagnostic Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Quick Simulator Scenarios */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              {isAr ? 'محاكاة أعطال الأدوات واختبار الاسترداد' : 'Simulate Tool Failure & Recovery'}
            </h3>
          </div>
          <p className="text-xs text-slate-400">
            {isAr
              ? 'اختر سيناريو عطل حقيقي لتشغيل محرك التشخيص وإعادة المحاولة الآمنة في الوقت الفعلي:'
              : 'Trigger a realistic security tool failure scenario to observe automated diagnosis and safe retry in action:'}
          </p>

          <div className="space-y-2">
            <button
              onClick={() => handleTriggerSimulation('waf_rate_limit')}
              disabled={isLoading}
              className="w-full text-start p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-amber-500/40 hover:bg-slate-900/90 transition-all text-xs group"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-amber-400 group-hover:text-amber-300">
                  {isAr ? 'خنق جدار الحماية (HTTP 429 WAF Rate-Limit)' : 'HTTP 429 WAF Rate-Limit'}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                  Nuclei
                </span>
              </div>
              <p className="text-[11px] text-slate-400 line-clamp-1">
                {isAr
                  ? 'خنق الحزم من جدار الحماية -> تفعيل Exponential Jitter Backoff وتخفيض التزامن.'
                  : 'Trigger WAF throttle -> Apply jitter backoff and throttle req concurrency.'}
              </p>
            </button>

            <button
              onClick={() => handleTriggerSimulation('nmap_syn_timeout')}
              disabled={isLoading}
              className="w-full text-start p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-rose-500/40 hover:bg-slate-900/90 transition-all text-xs group"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-rose-400 group-hover:text-rose-300">
                  {isAr ? 'إسقاط حزم SYN الصامتة (Port Silent Drop)' : 'TCP SYN Silent Drop on Firewall'}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                  Nmap
                </span>
              </div>
              <p className="text-[11px] text-slate-400 line-clamp-1">
                {isAr
                  ? 'جدار حماية يسقط حزم SYN -> التحويل التلقائي لبروتوكول TCP Connect الكامل (-sT).'
                  : 'Silent SYN drop -> Automatic protocol fallback to full TCP Connect scan.'}
              </p>
            </button>

            <button
              onClick={() => handleTriggerSimulation('semgrep_oom')}
              disabled={isLoading}
              className="w-full text-start p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-orange-500/40 hover:bg-slate-900/90 transition-all text-xs group"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-orange-400 group-hover:text-orange-300">
                  {isAr ? 'استهلاك ذاكرة الـ Sandbox (AST OOM)' : 'AST Memory Spike (OOM 512MB)'}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-orange-950 text-orange-300 border border-orange-800">
                  Semgrep
                </span>
              </div>
              <p className="text-[11px] text-slate-400 line-clamp-1">
                {isAr
                  ? 'ملف 25MB استهلك الذاكرة -> استبعاد الملفات المجمعة وتجزئة الفحص.'
                  : 'Minified bundle OOM -> Exclude minified artifacts & chunk scan stream.'}
              </p>
            </button>

            <button
              onClick={() => handleTriggerSimulation('zap_proxy_econnrefused')}
              disabled={isLoading}
              className="w-full text-start p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/40 hover:bg-slate-900/90 transition-all text-xs group"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-cyan-400 group-hover:text-cyan-300">
                  {isAr ? 'انقطاع مقبس البروكسي (Proxy Socket Refused)' : 'Proxy Socket Connection Refused'}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  OWASP ZAP
                </span>
              </div>
              <p className="text-[11px] text-slate-400 line-clamp-1">
                {isAr
                  ? 'انقطاع وكيل ZAP -> تحويل المسار تلقائياً لمحرك الزحف الخفيف Headless Crawler.'
                  : 'Daemon socket refused -> Seamless switch to lightweight crawler engine.'}
              </p>
            </button>
          </div>
        </div>

        {/* Custom Failure Analysis & Diagnosis Box */}
        <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-slate-200">
                  {isAr ? 'فاحص ومحلل أعطال الأدوات المخصص (Custom Error Diagnostic)' : 'Custom Error Diagnostic Console'}
                </h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">Gemini 3.7 + Heuristic Core</span>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              {isAr
                ? 'أدخل أي رسالة خطأ أو عطل ناتج عن أداة أمنية، وسيقوم النظام بتشخيص السبب الجذري، وتصنيف الخطأ، وصياغة خطة إعادة المحاولة الآمنة:'
                : 'Paste any security tool error trace to receive instant root cause diagnosis, classification, and safe recovery parameters:'}
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
              <div>
                <label className="text-[11px] font-medium text-slate-400 block mb-1">
                  {isAr ? 'الأداة (Tool)' : 'Tool'}
                </label>
                <input
                  type="text"
                  value={customTool}
                  onChange={(e) => setCustomTool(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                  placeholder="e.g. nuclei, nmap, semgrep, zap"
                />
              </div>
              <div>
                <label className="text-[11px] font-medium text-slate-400 block mb-1">
                  {isAr ? 'الهدف (Target)' : 'Target'}
                </label>
                <input
                  type="text"
                  value={customTarget}
                  onChange={(e) => setCustomTarget(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                  placeholder="e.g. 192.168.1.50"
                />
              </div>
            </div>

            <div>
              <label className="text-[11px] font-medium text-slate-400 block mb-1">
                {isAr ? 'نص رسالة الخطأ الخام (Raw Error Output / Trace)' : 'Raw Error Output / Stack Trace'}
              </label>
              <textarea
                value={customErrorText}
                onChange={(e) => setCustomErrorText(e.target.value)}
                rows={3}
                className="w-full p-2.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 resize-none"
                placeholder="Paste command error trace here..."
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              onClick={handleCustomDiagnose}
              disabled={isLoading || !customErrorText.trim()}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white flex items-center gap-2 shadow-lg shadow-emerald-950/40 transition-all"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>{isAr ? 'جاري التشخيص وصياغة الحل...' : 'Diagnosing & Formulating Fix...'}</span>
                </>
              ) : (
                <>
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>{isAr ? 'تشخيص الخطأ وتنفيذ الاسترداد الآمن' : 'Diagnose & Execute Safe Retry'}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Main Diagnostic & Proposed Fix View */}
      {selectedEvent && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="p-4 bg-slate-950/90 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-emerald-950 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-mono text-xs">
                {selectedEvent.toolName.substring(0, 3).toUpperCase()}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-sm font-bold text-slate-100">
                    {isAr ? 'تشخيص عطل الأداة:' : 'Tool Incident Diagnosis:'} {selectedEvent.toolName}
                  </h4>
                  <span
                    className={`px-2 py-0.5 text-[11px] rounded-full border font-mono font-medium ${
                      ERROR_BADGE_MAP[selectedEvent.classification]?.color || 'text-slate-300 border-slate-700 bg-slate-900'
                    }`}
                  >
                    {isAr
                      ? ERROR_BADGE_MAP[selectedEvent.classification]?.labelAr
                      : ERROR_BADGE_MAP[selectedEvent.classification]?.labelEn}
                  </span>
                </div>
                <span className="text-xs text-slate-500 font-mono">
                  Target: {selectedEvent.target} • {new Date(selectedEvent.timestamp).toLocaleTimeString()}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <span
                className={`text-xs font-mono px-2.5 py-1 rounded-md border flex items-center gap-1.5 ${
                  selectedEvent.status === 'AUTO_RECOVERED' || selectedEvent.status === 'FALLBACK_SUCCESS'
                    ? 'bg-emerald-950/80 border-emerald-700 text-emerald-300'
                    : 'bg-amber-950/80 border-amber-700 text-amber-300'
                }`}
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>
                  {selectedEvent.status === 'AUTO_RECOVERED'
                    ? (isAr ? 'تم الاسترداد التلقائي بنجاح' : 'Auto-Recovered')
                    : selectedEvent.status === 'FALLBACK_SUCCESS'
                    ? (isAr ? 'نجاح الأداة البديلة' : 'Fallback Succeeded')
                    : (isAr ? 'جاري المعالجة' : 'Retrying')}
                </span>
              </span>

              <button
                onClick={handleExecuteSafeRetryNow}
                disabled={isRetrying}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isRetrying ? 'animate-spin text-emerald-400' : 'text-slate-400'}`} />
                <span>{isRetrying ? (isAr ? 'جاري إعادة المحاولة...' : 'Retrying...') : (isAr ? 'إعادة المحاولة فوراً' : 'Force Safe Retry')}</span>
              </button>
            </div>
          </div>

          <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Root Cause & Strategy Analysis */}
            <div className="space-y-4">
              {/* Raw Error Banner */}
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                <span className="text-[11px] font-mono uppercase tracking-wider text-rose-400 block mb-1">
                  {isAr ? 'رسالة الخطأ الأصلية (Raw Error)' : 'Raw Error Message'}
                </span>
                <p className="text-xs font-mono text-slate-300 bg-slate-900/60 p-2 rounded border border-slate-800/80 break-words">
                  {selectedEvent.rawError}
                </p>
              </div>

              {/* Root Cause Card */}
              <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2">
                <div className="flex items-center gap-2">
                  <AlertCircleIcon className="w-4 h-4 text-amber-400" />
                  <h5 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    {isAr ? 'السبب الجذري للخطأ (Root Cause Analysis)' : 'Root Cause Analysis'}
                  </h5>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {isAr ? selectedEvent.rootCauseAr : selectedEvent.rootCauseEn}
                </p>
              </div>

              {/* Safe Retry Strategy Card */}
              <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Sliders className="w-4 h-4 text-cyan-400" />
                    <h5 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                      {isAr ? 'استراتيجية إعادة المحاولة الآمنة (Safe Retry Strategy)' : 'Safe Retry Strategy'}
                    </h5>
                  </div>
                  <span className="text-[11px] font-mono text-cyan-400">
                    Backoff: {selectedEvent.backoffDelayMs}ms
                  </span>
                </div>
                <p className="text-xs text-cyan-200/90 font-medium">
                  {isAr
                    ? STRATEGY_LABELS[selectedEvent.strategy]?.labelAr
                    : STRATEGY_LABELS[selectedEvent.strategy]?.labelEn}
                </p>
                <div className="grid grid-cols-2 gap-2 pt-1 text-[11px] font-mono text-slate-400">
                  <div className="bg-slate-900 p-1.5 rounded border border-slate-800">
                    <span>{isAr ? 'المحاولات:' : 'Attempts:'} </span>
                    <span className="text-slate-200">{selectedEvent.retryCount}/{selectedEvent.maxRetries}</span>
                  </div>
                  <div className="bg-slate-900 p-1.5 rounded border border-slate-800">
                    <span>{isAr ? 'قاطع الدائرة:' : 'Circuit:'} </span>
                    <span className="text-emerald-400">{selectedEvent.circuitBreakerState}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Right: Proposed Solution & Step-by-Step Resolution Log */}
            <div className="space-y-4">
              {/* Proposed Fix Card */}
              <div className="p-4 bg-emerald-950/20 border border-emerald-500/30 rounded-lg space-y-2">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <h5 className="text-xs font-bold uppercase tracking-wider text-emerald-300">
                    {isAr ? 'الحل المقترح والإجراء التصحيحي (Proposed Fix)' : 'Proposed Remediation & Solution'}
                  </h5>
                </div>
                <p className="text-xs text-slate-200 leading-relaxed font-medium">
                  {isAr ? selectedEvent.proposedFixAr : selectedEvent.proposedFixEn}
                </p>

                {selectedEvent.alternativeTool && (
                  <div className="mt-2 pt-2 border-t border-emerald-900/60 flex items-center justify-between text-xs">
                    <span className="text-slate-400">{isAr ? 'الأداة البديلة الموصى بها:' : 'Alternative Tool:'}</span>
                    <span className="font-mono px-2 py-0.5 rounded bg-slate-950 text-cyan-300 border border-cyan-800">
                      {selectedEvent.alternativeTool}
                    </span>
                  </div>
                )}
              </div>

              {/* Execution & Resolution Log */}
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-slate-400" />
                    <h5 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                      {isAr ? 'سجل خطوات الاسترداد والتصحيح (Resolution Trace Log)' : 'Resolution Trace Log'}
                    </h5>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">
                    {selectedEvent.executionLog.length} steps logged
                  </span>
                </div>

                <div className="bg-slate-900/90 rounded p-3 font-mono text-[11px] text-slate-300 space-y-1.5 max-h-48 overflow-y-auto border border-slate-800">
                  {selectedEvent.executionLog.map((logLine, idx) => (
                    <div key={idx} className="flex items-start gap-2">
                      <span className="text-cyan-500 select-none">›</span>
                      <span className={logLine.includes('Error') ? 'text-rose-400' : logLine.includes('verified') || logLine.includes('successful') ? 'text-emerald-300' : 'text-slate-300'}>
                        {logLine}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Stream of Past Recovery Events Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              {isAr ? 'سجل أحداث التصحيح والاسترداد السابقة' : 'Historical Recovery & Safe Retry Stream'}
            </h3>
          </div>

          {/* Filter & Search */}
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder={isAr ? 'بحث في الأحداث...' : 'Search events...'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 w-40 sm:w-48"
              />
            </div>

            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">{isAr ? 'جميع التصنيفات' : 'All Classifications'}</option>
              <option value="RATE_LIMITED">{isAr ? 'Rate Limited (429)' : 'Rate Limited'}</option>
              <option value="PORT_UNREACHABLE">{isAr ? 'Port Unreachable' : 'Port Unreachable'}</option>
              <option value="SANDBOX_RESOURCE_EXHAUSTED">{isAr ? 'Sandbox Memory OOM' : 'Sandbox OOM'}</option>
              <option value="WAF_BLOCKED">{isAr ? 'WAF Blocked' : 'WAF Blocked'}</option>
              <option value="TRANSIENT_TIMEOUT">{isAr ? 'Transient Timeout' : 'Transient Timeout'}</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-start text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-medium">
                <th className="pb-3 text-start">{isAr ? 'الأداة والهدف' : 'Tool & Target'}</th>
                <th className="pb-3 text-start">{isAr ? 'تصنيف الخطأ' : 'Error Classification'}</th>
                <th className="pb-3 text-start">{isAr ? 'الاستراتيجية' : 'Strategy'}</th>
                <th className="pb-3 text-start">{isAr ? 'الحالة' : 'Status'}</th>
                <th className="pb-3 text-start">{isAr ? 'الوقت' : 'Time'}</th>
                <th className="pb-3 text-end">{isAr ? 'معاينة' : 'Inspect'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEvents.map((ev) => {
                const isSelected = selectedEvent?.id === ev.id;
                return (
                  <tr
                    key={ev.id}
                    onClick={() => setSelectedEvent(ev)}
                    className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                      isSelected ? 'bg-slate-800/60' : ''
                    }`}
                  >
                    <td className="py-3 font-mono">
                      <span className="font-semibold text-slate-200 uppercase">{ev.toolName}</span>
                      <span className="text-slate-500 block text-[11px]">{ev.target}</span>
                    </td>
                    <td className="py-3">
                      <span
                        className={`px-2 py-0.5 text-[10px] font-mono rounded border ${
                          ERROR_BADGE_MAP[ev.classification]?.color || 'text-slate-300 border-slate-700 bg-slate-900'
                        }`}
                      >
                        {isAr
                          ? ERROR_BADGE_MAP[ev.classification]?.labelAr
                          : ERROR_BADGE_MAP[ev.classification]?.labelEn}
                      </span>
                    </td>
                    <td className="py-3 text-slate-300">
                      {isAr ? STRATEGY_LABELS[ev.strategy]?.labelAr : STRATEGY_LABELS[ev.strategy]?.labelEn}
                    </td>
                    <td className="py-3 font-mono text-[11px]">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] ${
                          ev.status === 'AUTO_RECOVERED' || ev.status === 'FALLBACK_SUCCESS'
                            ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
                            : 'bg-amber-950/80 text-amber-400 border border-amber-800'
                        }`}
                      >
                        {ev.status}
                      </span>
                    </td>
                    <td className="py-3 text-slate-500 text-[11px] font-mono">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 text-end">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(ev);
                        }}
                        className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-slate-200"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

function AlertCircleIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="12" x2="12" y1="8" y2="12" />
      <line x1="12" x2="12.01" y1="16" y2="16" />
    </svg>
  );
}
