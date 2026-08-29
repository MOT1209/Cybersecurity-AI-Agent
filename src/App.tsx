/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { OrchestratorDashboard } from './components/OrchestratorDashboard';
import { SecurityGatewayManager } from './components/SecurityGatewayManager';
import { AgentWorkspace } from './components/AgentWorkspace';
import { CodeAuditor } from './components/CodeAuditor';
import { InteractiveTerminalLab } from './components/InteractiveTerminalLab';
import { CyberToolbox } from './components/CyberToolbox';
import { KnowledgeBase } from './components/KnowledgeBase';
import { CtfArena } from './components/CtfArena';
import { ReportBuilder } from './components/ReportBuilder';
import { ErrorRecoveryCenter } from './components/ErrorRecoveryCenter';
import { CTFScenario } from './types';
import { Shield, ShieldAlert, Cpu, Sparkles, Terminal } from 'lucide-react';
import { apiFetch } from './lib/api';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('orchestrator');
  const [language, setLanguage] = useState<'ar' | 'en'>('ar');
  const [serverHealth, setServerHealth] = useState<{ status: string; platform?: string; timestamp?: string } | null>(null);

  const isAr = language === 'ar';

  useEffect(() => {
    // Check server backend health
    apiFetch('/api/health')
      .then((res) => res.json())
      .then((data) => setServerHealth(data))
      .catch((err) => console.warn('Server health check notice:', err));
  }, []);

  // Update HTML document dir attribute when language toggles
  useEffect(() => {
    document.documentElement.dir = isAr ? 'rtl' : 'ltr';
    document.documentElement.lang = isAr ? 'ar' : 'en';
  }, [isAr]);

  const handleAskAgentAboutChallenge = (scenario: CTFScenario) => {
    setActiveTab('orchestrator');
  };

  return (
    <div className={`min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200 ${isAr ? 'font-sans' : ''}`}>
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        language={language}
        setLanguage={setLanguage}
      />

      {/* Main Tab Views */}
      <main className="flex-1 pb-10">
        {activeTab === 'orchestrator' && <OrchestratorDashboard language={language} />}
        {activeTab === 'recovery' && <ErrorRecoveryCenter language={language} />}
        {activeTab === 'gateway' && <SecurityGatewayManager language={language} />}
        {activeTab === 'agent' && <AgentWorkspace language={language} />}
        {activeTab === 'auditor' && <CodeAuditor language={language} />}
        {activeTab === 'terminal' && <InteractiveTerminalLab language={language} />}
        {activeTab === 'toolbox' && <CyberToolbox language={language} />}
        {activeTab === 'knowledge' && <KnowledgeBase language={language} />}
        {activeTab === 'ctf' && (
          <CtfArena
            language={language}
            onAskAgentAboutChallenge={handleAskAgentAboutChallenge}
          />
        )}
        {activeTab === 'report' && <ReportBuilder language={language} />}
      </main>

      {/* Bottom Status Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/95 py-3 px-4 sm:px-8 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1 text-slate-400 font-mono">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>CYBERGUARD AI Core v3.0 Multi-Agent</span>
            </span>
            <span>•</span>
            <span className="text-[11px]">
              {isAr ? 'منصة الأمن السيبراني متعددة الوكلاء والتحقق الآلي' : 'Enterprise Multi-Agent Cybersecurity Platform'}
            </span>
          </div>

          <div className="flex items-center gap-3 text-[11px]">
            <span className="flex items-center gap-1 text-emerald-400 font-mono">
              <Shield className="w-3.5 h-3.5" />
              <span>{isAr ? 'بيئة معزولة Sandbox + Zero-Trust Gateway' : 'Zero-Trust Gateway & Sandbox'}</span>
            </span>
            <span>•</span>
            <span>Gemini 3.7 Flash Engine</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
