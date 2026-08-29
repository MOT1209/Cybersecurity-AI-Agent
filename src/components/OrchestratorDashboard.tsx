import React, { useState } from 'react';
import { apiFetch } from '../lib/api';
import {
  Play,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Layers,
  Sparkles,
  Terminal,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Radar,
  Globe,
  Code2,
  Network,
  Cloud,
  Boxes,
  FileSearch,
  Crosshair,
  Wrench,
  FileText,
  CheckCheck,
  ChevronRight,
  ExternalLink,
  Lock,
  Copy,
  Check,
  RotateCcw,
  RefreshCw,
  Sliders,
  AlertOctagon,
  Activity
} from 'lucide-react';
import { SYSTEM_AGENTS, INITIAL_PROJECT_SCOPES } from '../data/agentPlatformData';
import { OrchestrationPlan, AgentType, ErrorRecoveryEvent } from '../types';

interface OrchestratorDashboardProps {
  language: 'ar' | 'en';
}

const AGENT_ICON_MAP: Record<string, React.ReactNode> = {
  Radar: <Radar className="w-4 h-4" />,
  Globe: <Globe className="w-4 h-4" />,
  ShieldAlert: <ShieldAlert className="w-4 h-4" />,
  Code2: <Code2 className="w-4 h-4" />,
  Network: <Network className="w-4 h-4" />,
  Cloud: <Cloud className="w-4 h-4" />,
  Boxes: <Boxes className="w-4 h-4" />,
  FileSearch: <FileSearch className="w-4 h-4" />,
  Crosshair: <Crosshair className="w-4 h-4" />,
  Wrench: <Wrench className="w-4 h-4" />,
  FileText: <FileText className="w-4 h-4" />,
  CheckCheck: <CheckCheck className="w-4 h-4" />,
};

export const OrchestratorDashboard: React.FC<OrchestratorDashboardProps> = ({ language }) => {
  const isAr = language === 'ar';

  const [prompt, setPrompt] = useState<string>(
    isAr
      ? 'قم بإجراء فحص أمني شامل وكشف للمنافذ المفتوحة وتدقيق ثغرات الويب والتحقق من صحتها وتوليد كود الترقيع للهدف'
      : 'Perform full reconnaissance, web vulnerability probing, finding validation, and remediation patch synthesis for the target.'
  );
  const [target, setTarget] = useState<string>('192.168.1.50');
  const [selectedProject, setSelectedProject] = useState<string>('proj_alpha_lab');
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [currentPlan, setCurrentPlan] = useState<OrchestrationPlan | null>(null);
  const [selectedAgentDetail, setSelectedAgentDetail] = useState<AgentType | null>('recon');
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'workflow' | 'live_logs' | 'findings' | 'agents_mesh'>('workflow');
  const [recoveringStepId, setRecoveringStepId] = useState<string | null>(null);
  const [stepRecoveryFeedback, setStepRecoveryFeedback] = useState<Record<string, {
    rootCause: string;
    proposedFix: string;
    strategy: string;
    status: string;
  }>>({});

  const handleSimulateStepErrorAndRecover = (stepId: string, toolName: string = 'Security Tool') => {
    setRecoveringStepId(stepId);
    
    // Simulate immediate error detection & safe retry
    setTimeout(() => {
      setStepRecoveryFeedback((prev) => ({
        ...prev,
        [stepId]: {
          rootCause: isAr
            ? `تم رصد خنق جدار الحماية (HTTP 429 / WAF Rate Limit) أثناء تنفيذ ${toolName}.`
            : `Detected WAF rate limit (HTTP 429) during ${toolName} execution.`,
          proposedFix: isAr
            ? `تطبيق تأخير أسي آمن (Backoff 2000ms) وتخفيض التزامن وإعادة المحاولة التلقائية.`
            : `Applied safe exponential backoff (2000ms), throttled concurrency, and retried automatically.`,
          strategy: 'THROTTLE_AND_RETRY',
          status: 'AUTO_RECOVERED',
        },
      }));
      setRecoveringStepId(null);
    }, 1500);
  };

  const handleRunMission = async () => {
    if (!prompt.trim()) return;
    setIsRunning(true);

    try {
      const response = await apiFetch('/api/orchestrator/run-mission', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userPrompt: prompt,
          target,
          projectId: selectedProject,
          language,
        }),
      });

      if (!response.ok) {
        const errData = await response.json();
        alert(errData.details || errData.error || 'Failed to execute mission');
        setIsRunning(false);
        return;
      }

      const plan: OrchestrationPlan = await response.json();
      setCurrentPlan(plan);
      setActiveTab('workflow');
    } catch (err: any) {
      console.error('Mission execution error:', err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleCopyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCodeId(id);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  const quickScenarios = [
    {
      titleAr: 'فحص شامل واكتشاف ثغرات الويب و SQLi',
      titleEn: 'Full Recon & Web SQLi Discovery',
      target: '192.168.1.50',
      prompt: isAr
        ? 'ابدأ مرحلة الاستطلاع وكشف المنافذ، ثم افحص واجهات الـ REST API وتحقق من ثغرات الحقن وصياغة كود الترقيع.'
        : 'Recon open ports, audit REST API endpoints for SQLi, validate proof-of-concept, and formulate secure patches.',
    },
    {
      titleAr: 'تدقيق أمان الحاويات وكوبرنيتس (K8s)',
      titleEn: 'Container & K8s RBAC Audit',
      target: '192.168.1.51',
      prompt: isAr
        ? 'فحص إعدادات الحاويات وصلاحيات Docker Socket والتحقق من مخاطر الهروب من الحاوية (Container Escape).'
        : 'Audit Docker container layers, check socket exposure, and analyze container escape vectors.',
    },
    {
      titleAr: 'فحص الشيفرة المصدرية وتدقيق SAST للأسرار',
      titleEn: 'Source Code SAST & Secret Leak Audit',
      target: '127.0.0.1 (Source Repo)',
      prompt: isAr
        ? 'فحص الكود المصدري عبر قواعد Semgrep واكتشاف المفاتيح المسربة وثغرات OWASP وتقديم الترقيعات.'
        : 'Audit source code repositories with Semgrep, detect hardcoded secrets, and generate secure code fixes.',
    },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-cyan-500/20 rounded-2xl p-6 relative overflow-hidden backdrop-blur-md">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono bg-cyan-500/10 border border-cyan-500/30 text-cyan-300">
              <Cpu className="w-3.5 h-3.5 animate-pulse" />
              <span>{isAr ? 'العقل المدبر ومنسق الوكلاء' : 'Autonomous AI Orchestrator'}</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
              <Shield className="w-8 h-8 text-cyan-400" />
              <span>CYBERGUARD Multi-Agent Collective</span>
            </h1>
            <p className="text-slate-400 text-sm max-w-2xl">
              {isAr
                ? 'نظام أمني متكامل ينسق 12 وكيلاً متخصصاً وفق الدورة الكاملة: الاستيعاب ➔ التحليل ➔ التخطيط ➔ التفويض الأمني ➔ التنفيذ ➔ الملاحظة ➔ التحقق ➔ الترقيع ➔ إعادة الاختبار ➔ التقرير.'
                : 'Enterprise multi-agent framework coordinating 12 specialized cybersecurity agents with mandatory Security Gateway enforcement and automated finding validation.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-center min-w-[100px]">
              <div className="text-xl font-mono font-bold text-cyan-400">12</div>
              <div className="text-[11px] text-slate-400">{isAr ? 'وكلاء متخصصون' : 'Active Agents'}</div>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-center min-w-[100px]">
              <div className="text-xl font-mono font-bold text-emerald-400">8</div>
              <div className="text-[11px] text-slate-400">{isAr ? 'أدوات Sandbox' : 'Sandbox Tools'}</div>
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-center min-w-[100px]">
              <div className="text-xl font-mono font-bold text-indigo-400">100%</div>
              <div className="text-[11px] text-slate-400">{isAr ? 'عزل أمني' : 'Sandbox Isolation'}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Mission Dispatcher Controls */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span>{isAr ? 'إطلاق مهمة أمنية متعددة الوكلاء' : 'Launch Multi-Agent Security Mission'}</span>
          </div>

          {/* Project & Scope selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">{isAr ? 'مشروع النطاق:' : 'Project Scope:'}</span>
            <select
              value={selectedProject}
              onChange={(e) => setSelectedProject(e.target.value)}
              className="bg-slate-950 border border-slate-700 text-xs text-cyan-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500"
            >
              {INITIAL_PROJECT_SCOPES.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.targetDomain})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Input Form */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="lg:col-span-3 space-y-2">
            <label className="text-xs font-mono text-slate-400 block">
              {isAr ? 'أمر المهمة / استفسار الفحص الأمني:' : 'Security Mission Objective / Prompt:'}
            </label>
            <textarea
              rows={2}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder={
                isAr
                  ? 'اكتب هدف المهمة وسيتولى الـ Orchestrator توزيع الأدوار بين الوكلاء...'
                  : 'Describe the security objective. The Orchestrator will delegate across agents...'
              }
              className="w-full bg-slate-950/90 border border-slate-800 rounded-xl p-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors resize-none font-sans"
            />
          </div>

          <div className="space-y-2 flex flex-col justify-between">
            <div>
              <label className="text-xs font-mono text-slate-400 block">
                {isAr ? 'الهدف المصرح به (Target IP / Host):' : 'Authorized Target (IP/Host):'}
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="w-full bg-slate-950/90 border border-slate-800 rounded-xl px-3 py-2 text-sm text-cyan-400 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              onClick={handleRunMission}
              disabled={isRunning || !prompt.trim()}
              className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold px-4 py-2.5 rounded-xl transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 text-sm mt-2"
            >
              {isRunning ? (
                <>
                  <Clock className="w-4 h-4 animate-spin" />
                  <span>{isAr ? 'جاري التنسيق والتنفيذ...' : 'Orchestrating Agents...'}</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>{isAr ? 'تنفيذ المهمة عبر الوكلاء' : 'Execute Mission'}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick presets */}
        <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500">{isAr ? 'سيناريوهات سريعة:' : 'Quick Presets:'}</span>
          {quickScenarios.map((sc, idx) => (
            <button
              key={idx}
              onClick={() => {
                setPrompt(sc.prompt);
                setTarget(sc.target);
              }}
              className="text-xs px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 transition-colors"
            >
              {isAr ? sc.titleAr : sc.titleEn}
            </button>
          ))}
        </div>
      </div>

      {/* Tabs Navigation for Results */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('workflow')}
            className={`px-4 py-2 text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 ${
              activeTab === 'workflow'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>{isAr ? 'مخطط سير العمل المنسق (Workflow Steps)' : 'Orchestrated Workflow'}</span>
          </button>

          <button
            onClick={() => setActiveTab('findings')}
            className={`px-4 py-2 text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 ${
              activeTab === 'findings'
                ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>
              {isAr ? 'الثغرات الموثقة وكود الترقيع' : 'Validated Findings & Patches'}
              {currentPlan?.generatedFindings?.length ? ` (${currentPlan.generatedFindings.length})` : ''}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('live_logs')}
            className={`px-4 py-2 text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 ${
              activeTab === 'live_logs'
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>{isAr ? 'سجل النشاط المباشر (Audit & Trace Logs)' : 'Live Trace & Audit Logs'}</span>
          </button>

          <button
            onClick={() => setActiveTab('agents_mesh')}
            className={`px-4 py-2 text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 ${
              activeTab === 'agents_mesh'
                ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>{isAr ? 'شبكة الوكلاء الـ 12 المتخصصة' : '12-Agent Mesh Collective'}</span>
          </button>
        </div>

        {currentPlan && (
          <div className="text-xs text-slate-500 font-mono flex items-center gap-2">
            <span>Trace ID:</span>
            <span className="text-cyan-400 font-semibold">{currentPlan.traceId}</span>
          </div>
        )}
      </div>

      {/* Tab Content: Workflow */}
      {activeTab === 'workflow' && (
        <div className="space-y-4">
          {!currentPlan && (
            <div className="bg-slate-900/50 border border-slate-800/80 rounded-2xl p-12 text-center space-y-3">
              <Cpu className="w-10 h-10 text-cyan-400 mx-auto opacity-70 animate-pulse" />
              <h3 className="text-base font-semibold text-slate-200">
                {isAr ? 'لا توجد مهمة قيد التشغيل حالياً' : 'No active mission execution'}
              </h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                {isAr
                  ? 'اختر أحد السيناريوهات السريعة أعلاه أو اكتب هدف المهمة واضغط "تنفيذ المهمة عبر الوكلاء" لمشاهدة التنسيق المتعدد للوكلاء.'
                  : 'Select a preset or enter a mission objective above and click Execute Mission to observe multi-agent orchestration in real time.'}
              </p>
            </div>
          )}

          {currentPlan && (
            <div className="space-y-4">
              {/* Summary card */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex items-start gap-3">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="text-sm font-semibold text-slate-100">
                    {isAr ? 'ملخص إنجاز المهمة الأمني' : 'Mission Assessment Summary'}
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {isAr ? currentPlan.summaryAr : currentPlan.summaryEn}
                  </p>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {currentPlan.participatingAgents.map((ag) => (
                      <span
                        key={ag}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/50 text-cyan-300"
                      >
                        @{ag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Step by Step Timeline */}
              <div className="space-y-3">
                {currentPlan.steps.map((st) => {
                  const recovery = stepRecoveryFeedback[st.id];
                  const isRecovering = recoveringStepId === st.id;

                  return (
                    <div
                      key={st.id}
                      className="bg-slate-900/80 border border-slate-800/90 rounded-xl p-4 space-y-3 hover:border-slate-700 transition-colors"
                    >
                      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                        <div className="flex items-start gap-3">
                          <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center font-mono font-bold text-xs shrink-0">
                            {st.stepNumber}
                          </div>
                          <div className="space-y-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-mono font-semibold text-slate-200 uppercase">
                                [{st.phase}]
                              </span>
                              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/50">
                                {st.agent}
                              </span>
                              {st.toolName && (
                                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                                  🔧 {st.toolName}
                                </span>
                              )}
                              {recovery && (
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center gap-1">
                                  <RotateCcw className="w-2.5 h-2.5" />
                                  <span>Self-Healed</span>
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-slate-300">{st.outputSummary}</p>
                            <div className="text-[11px] text-slate-500 font-mono">{st.detailedLog}</div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0 self-end md:self-center">
                          <button
                            onClick={() => handleSimulateStepErrorAndRecover(st.id, st.toolName || 'Security Tool')}
                            disabled={isRecovering}
                            title={isAr ? 'محاكاة عطل وتشغيل الاسترداد الآمن' : 'Simulate Failure & Test Safe Retry'}
                            className="px-2 py-1 text-[11px] rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1 transition-colors"
                          >
                            <RotateCcw className={`w-3 h-3 ${isRecovering ? 'animate-spin text-cyan-400' : 'text-slate-400'}`} />
                            <span>{isRecovering ? (isAr ? 'جاري الاسترداد...' : 'Recovering...') : (isAr ? 'اختبار الاسترداد الآمن' : 'Test Safe Retry')}</span>
                          </button>

                          <span className="text-[11px] font-mono text-slate-400">{st.durationMs}ms</span>
                          <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 bg-emerald-950/60 border border-emerald-800/50 px-2 py-0.5 rounded">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>{recovery ? 'COMPLETED (SAFE RETRIED)' : st.status}</span>
                          </span>
                        </div>
                      </div>

                      {/* Inline Error Recovery Diagnostic Box if triggered */}
                      {recovery && (
                        <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-lg text-xs space-y-1.5 animate-in fade-in duration-300">
                          <div className="flex items-center justify-between text-[11px] font-mono font-semibold text-emerald-400">
                            <span className="flex items-center gap-1.5">
                              <ShieldCheck className="w-3.5 h-3.5" />
                              <span>{isAr ? 'تم تشخيص العطل والاسترداد التلقائي الآمن (Safe Recovery Resolved)' : 'Automated Error Recovery & Safe Retry Applied'}</span>
                            </span>
                            <span>Strategy: {recovery.strategy}</span>
                          </div>
                          <div className="text-slate-300 text-[11px]">
                            <strong className="text-slate-400">{isAr ? 'السبب الجذري: ' : 'Root Cause: '}</strong>
                            {recovery.rootCause}
                          </div>
                          <div className="text-emerald-300 text-[11px]">
                            <strong className="text-emerald-400">{isAr ? 'الإجراء التصحيحي: ' : 'Proposed Fix: '}</strong>
                            {recovery.proposedFix}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab Content: Findings & Patches */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {(!currentPlan || !currentPlan.generatedFindings || currentPlan.generatedFindings.length === 0) && (
            <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 text-xs">
              {isAr ? 'لم يتم توليد ثغرات بعد. قم بتنفيذ مهمة لفحص واكتشاف الثغرات وتوليد كود الترقيع.' : 'No findings logged yet. Execute a mission to detect and validate findings.'}
            </div>
          )}

          {currentPlan?.generatedFindings?.map((find) => (
            <div
              key={find.id}
              className="bg-slate-900/90 border border-rose-500/20 rounded-xl p-5 space-y-4"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800/60">
                      {find.severity} (CVSS {find.cvssScore})
                    </span>
                    <span className="text-xs font-mono text-slate-400">{find.cwe}</span>
                  </div>
                  <h3 className="text-base font-bold text-slate-100">{find.title}</h3>
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  {isAr ? 'الهدف المصاب:' : 'Affected Target:'} <span className="text-cyan-400">{find.target}</span>
                </div>
              </div>

              {/* Description & Evidence */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
                <div className="space-y-2">
                  <div className="font-semibold text-slate-300">{isAr ? 'الوصف والأثر الأمني:' : 'Description & Impact:'}</div>
                  <p className="text-slate-400 leading-relaxed">{find.description}</p>
                  <p className="text-slate-400 leading-relaxed font-semibold text-rose-300">{find.impact}</p>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                    <div className="font-semibold text-emerald-400 text-[11px] flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{isAr ? 'التحقق واستبعاد الإيجابيات الكاذبة (Finding Validation):' : 'Validation Trace:'}</span>
                    </div>
                    <p className="text-slate-400 text-[11px]">{find.validation.falsePositiveAnalysis}</p>
                    <div className="text-[10px] text-slate-500 font-mono">
                      Validated by: @{find.validation.validatedByAgent} (Confidence: {find.validation.confidenceScore}%)
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="font-semibold text-slate-300">{isAr ? 'دليل الإثبات (PoC Evidence):' : 'Proof of Concept Evidence:'}</div>
                  <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                    {find.evidence}
                  </pre>
                </div>
              </div>

              {/* Remediation Patch & Code */}
              {find.remediation && (
                <div className="bg-slate-950/90 border border-emerald-500/20 rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
                      <Wrench className="w-4 h-4" />
                      <span>{isAr ? 'كود الترقيع والتحصين المقترح من وكيل Remediation Agent:' : 'Remediation Patch:'}</span>
                    </div>
                    {find.remediation.codeFix && (
                      <button
                        onClick={() => handleCopyCode(find.remediation.codeFix!, find.id)}
                        className="text-[11px] flex items-center gap-1 text-slate-400 hover:text-emerald-400 px-2 py-1 rounded bg-slate-900 border border-slate-800 transition-colors"
                      >
                        {copiedCodeId === find.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedCodeId === find.id ? (isAr ? 'تم النسخ!' : 'Copied!') : (isAr ? 'نسخ الكود' : 'Copy Code')}</span>
                      </button>
                    )}
                  </div>

                  <p className="text-xs text-slate-300">{find.remediation.summary}</p>

                  {find.remediation.codeFix && (
                    <pre className="bg-slate-900/90 p-3 rounded-lg border border-slate-800 text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                      {find.remediation.codeFix}
                    </pre>
                  )}

                  {find.remediation.configPatch && (
                    <div className="space-y-1">
                      <div className="text-[11px] text-slate-400 font-mono">{isAr ? 'قاعدة جدار الحماية (WAF / Web Config):' : 'WAF / Config Patch:'}</div>
                      <pre className="bg-slate-900/90 p-2.5 rounded border border-slate-800 text-[11px] font-mono text-amber-300 overflow-x-auto whitespace-pre-wrap">
                        {find.remediation.configPatch}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Tab Content: Live Trace & Audit Logs */}
      {activeTab === 'live_logs' && (
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs space-y-2">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-slate-400">
            <span className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>{isAr ? 'سجل تتبع الوكلاء وبوابة الأمان (Security Gateway Logs)' : 'Orchestrator Trace Logs'}</span>
            </span>
            <span className="text-[11px] text-emerald-400">● Live Audit Enabled</span>
          </div>

          <div className="space-y-1.5 max-h-96 overflow-y-auto pr-2">
            {(currentPlan?.liveLogs || []).map((log, idx) => (
              <div key={idx} className="flex items-start gap-2 py-1 border-b border-slate-900/60">
                <span className="text-slate-500 text-[11px] shrink-0">{log.timestamp}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded font-bold shrink-0 ${
                    log.type === 'auth'
                      ? 'bg-purple-950 text-purple-300'
                      : log.type === 'finding'
                      ? 'bg-rose-950 text-rose-300'
                      : log.type === 'tool'
                      ? 'bg-blue-950 text-blue-300'
                      : log.type === 'success'
                      ? 'bg-emerald-950 text-emerald-300'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  [{log.emitter}]
                </span>
                <span className="text-slate-300">{log.message}</span>
              </div>
            ))}

            {(!currentPlan || !currentPlan.liveLogs) && (
              <div className="text-slate-500 py-8 text-center">
                {isAr ? 'لا توجد سجلات تتبع حالية. قم بتنفيذ مهمة لعرض تتبع الوكلاء المباشر.' : 'No trace logs yet. Launch a mission to monitor agent communication.'}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab Content: Agents Mesh */}
      {activeTab === 'agents_mesh' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {SYSTEM_AGENTS.map((agent) => (
            <div
              key={agent.id}
              onClick={() => setSelectedAgentDetail(agent.id)}
              className={`bg-slate-900/80 border rounded-xl p-4 space-y-3 cursor-pointer transition-all hover:scale-[1.01] ${
                selectedAgentDetail === agent.id
                  ? 'border-cyan-500 shadow-lg shadow-cyan-500/10'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <div className={`p-2 rounded-lg border ${agent.badgeColor}`}>
                    {AGENT_ICON_MAP[agent.icon] || <Cpu className="w-4 h-4" />}
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-100">{isAr ? agent.nameAr : agent.nameEn}</h4>
                    <span className="text-[10px] font-mono text-cyan-400">@{agent.id}</span>
                  </div>
                </div>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">
                {isAr ? agent.roleDescriptionAr : agent.roleDescriptionEn}
              </p>

              <div className="space-y-1.5 pt-2 border-t border-slate-800">
                <div className="text-[11px] font-mono text-slate-500">{isAr ? 'الأدوات المرتبطة:' : 'Tools:'}</div>
                <div className="flex flex-wrap gap-1">
                  {agent.tools.map((tool, idx) => (
                    <span
                      key={idx}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800"
                    >
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
