import React, { useState } from 'react';
import { apiFetch } from '../lib/api';
import {
  ShieldCheck,
  Lock,
  CheckCircle2,
  XCircle,
  Terminal,
  FolderLock,
  RefreshCw,
} from 'lucide-react';
import { INITIAL_PROJECT_SCOPES } from '../data/agentPlatformData';
import { GatewayCheckResult } from '../types';

interface SecurityGatewayManagerProps {
  language: 'ar' | 'en';
}

export const SecurityGatewayManager: React.FC<SecurityGatewayManagerProps> = ({ language }) => {
  const isAr = language === 'ar';

  const [testTarget, setTestTarget] = useState<string>('192.168.1.50');
  const [testTool, setTestTool] = useState<string>('nmap');
  const [selectedProjectId, setSelectedProjectId] = useState<string>('proj_alpha_lab');
  const [checkResult, setCheckResult] = useState<GatewayCheckResult | null>(null);
  const [isChecking, setIsChecking] = useState<boolean>(false);

  const currentProject =
    INITIAL_PROJECT_SCOPES.find((p) => p.id === selectedProjectId) || INITIAL_PROJECT_SCOPES[0];

  const handleTestGateway = async () => {
    setIsChecking(true);
    try {
      const res = await apiFetch('/api/gateway/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: testTarget,
          toolName: testTool,
          projectId: selectedProjectId,
        }),
      });
      const data = await res.json();
      setCheckResult(data);
    } catch (e) {
      console.error('Gateway check failed:', e);
    } finally {
      setIsChecking(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/90 border border-purple-500/20 rounded-2xl p-6 relative overflow-hidden backdrop-blur-md">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono bg-purple-500/10 border border-purple-500/30 text-purple-300">
              <Lock className="w-3.5 h-3.5" />
              <span>{isAr ? 'طبقة التحقق والتفويض الإلزامية' : 'Mandatory Security Gateway & Policy Engine'}</span>
            </div>
            <h2 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <ShieldCheck className="w-7 h-7 text-purple-400" />
              <span>Security Gateway & Scope Allowlist</span>
            </h2>
            <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
              {isAr
                ? 'تفرض بوابة الأمان فحصاً صارماً قبل تشغيل أي أداة أو تكليف أي وكيل: التحقق من النطاق المصرح به ➔ تقييم درجة خطورة الأداة ➔ العزل داخل بيئة Sandbox ➔ تسجيل وتوثيق عملية الفحص بالكامل.'
                : 'Zero-trust authorization layer ensuring agents only execute tools against authorized scopes with sandbox boundaries.'}
            </p>
          </div>
        </div>
      </div>

      {/* Grid: Scope Overview & Interactive Gateway Validator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Active Scope Specification */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <FolderLock className="w-4 h-4 text-cyan-400" />
                  <span>{currentProject.name}</span>
                </h3>
                <span className="text-xs text-slate-400 font-mono">Engagement ID: {currentProject.id}</span>
              </div>
              <span className="text-xs font-mono px-2.5 py-1 rounded bg-emerald-950/80 border border-emerald-800/60 text-emerald-300">
                ● {currentProject.environmentType}
              </span>
            </div>

            {/* Authorization Details */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
              <div className="flex items-center justify-between text-slate-400">
                <span>{isAr ? 'جهة التفويض والموافقة:' : 'Authorized By:'}</span>
                <span className="text-slate-200 font-mono">{currentProject.authorizationGrantedBy}</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>{isAr ? 'فترة الصلاحية:' : 'Engagement Validity:'}</span>
                <span className="text-slate-200 font-mono">
                  {currentProject.authorizationDate} ➔ {currentProject.validUntil}
                </span>
              </div>
            </div>

            {/* In-Scope vs Out-Of-Scope Lists */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="space-y-2 p-3 bg-emerald-950/20 border border-emerald-500/20 rounded-xl">
                <div className="font-semibold text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{isAr ? 'الأصول المسموحة (In-Scope Allowlist):' : 'In-Scope Allowlist:'}</span>
                </div>
                <ul className="space-y-1 text-slate-300 font-mono text-[11px]">
                  {currentProject.inScope.map((item, idx) => (
                    <li key={idx} className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="space-y-2 p-3 bg-rose-950/20 border border-rose-500/20 rounded-xl">
                <div className="font-semibold text-rose-400 flex items-center gap-1.5">
                  <XCircle className="w-4 h-4" />
                  <span>{isAr ? 'المحظورات الصارمة (Out-of-Scope Blacklist):' : 'Out-of-Scope Blacklist:'}</span>
                </div>
                <ul className="space-y-1 text-slate-300 font-mono text-[11px]">
                  {currentProject.outOfScope.map((item, idx) => (
                    <li key={idx} className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Live Gateway Simulator & Tester */}
        <div className="space-y-4">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-purple-400" />
              <span>{isAr ? 'محاكي فحص بوابة الأمان (Gateway Tester)' : 'Live Gateway Policy Tester'}</span>
            </h3>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">{isAr ? 'عنوان الهدف للاختبار:' : 'Test Target IP/Host:'}</label>
                <input
                  type="text"
                  value={testTarget}
                  onChange={(e) => setTestTarget(e.target.value)}
                  placeholder="e.g. 192.168.1.50 or 8.8.8.8"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-cyan-300 font-mono focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">{isAr ? 'الأداة المراد تشغيلها:' : 'Target Tool:'}</label>
                <select
                  value={testTool}
                  onChange={(e) => setTestTool(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-purple-500"
                >
                  <option value="nmap">Nmap Port Scanner (Low Risk)</option>
                  <option value="nuclei">Nuclei Vulnerability Engine (Medium Risk)</option>
                  <option value="semgrep">Semgrep SAST (Safe)</option>
                  <option value="zap">OWASP ZAP (High Risk / Requires Approval)</option>
                </select>
              </div>

              <button
                onClick={handleTestGateway}
                disabled={isChecking}
                className="w-full bg-purple-600 hover:bg-purple-500 text-white font-semibold py-2 rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : ''}`} />
                <span>{isAr ? 'التحقق من تصريح البوابة' : 'Verify with Security Gateway'}</span>
              </button>
            </div>

            {/* Check Result Display */}
            {checkResult && (
              <div
                className={`p-4 rounded-xl border space-y-2 text-xs ${
                  checkResult.isAllowed
                    ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
                    : 'bg-rose-950/40 border-rose-500/40 text-rose-200'
                }`}
              >
                <div className="flex items-center gap-2 font-bold">
                  {checkResult.isAllowed ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-rose-400" />}
                  <span>{checkResult.isAllowed ? (isAr ? 'مصرّح بالتنفيذ (ALLOWED)' : 'GATEWAY PERMISSION GRANTED') : (isAr ? 'مرفوض من البوابة (DENIED)' : 'GATEWAY BLOCKED')}</span>
                </div>
                <p className="text-[11px] leading-relaxed opacity-90">{checkResult.reason}</p>
                <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono">
                  <span>Scope: {checkResult.scopeValidation}</span>
                  <span>Tool Risk: {checkResult.toolRisk}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
