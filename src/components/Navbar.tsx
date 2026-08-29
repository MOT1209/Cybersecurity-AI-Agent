import React from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  Code2, 
  Wrench, 
  BookOpen, 
  Flag, 
  FileText, 
  Bot, 
  Sparkles,
  Globe,
  Cpu,
  Lock,
  Layers,
  RotateCcw
} from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  language: 'ar' | 'en';
  setLanguage: (lang: 'ar' | 'en') => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  language,
  setLanguage,
}) => {
  const isAr = language === 'ar';

  const navItems = [
    {
      id: 'orchestrator',
      labelAr: 'منسق الوكلاء (Orchestrator)',
      labelEn: 'AI Orchestrator',
      icon: Cpu,
      badge: '12 Agents',
    },
    {
      id: 'recovery',
      labelAr: 'تصحيح الأخطاء (Error Recovery)',
      labelEn: 'Safe Retry & Recovery',
      icon: RotateCcw,
      badge: 'Self-Healing',
    },
    {
      id: 'gateway',
      labelAr: 'بوابة الأمان والنطاق (Gateway)',
      labelEn: 'Security Gateway',
      icon: Lock,
      badge: 'Zero-Trust',
    },
    {
      id: 'agent',
      labelAr: 'المساعد الأمني الذكي',
      labelEn: 'AI Mentor Chat',
      icon: Bot,
      badge: 'Gemini 3.7',
    },
    {
      id: 'auditor',
      labelAr: 'فاحص الأكواد (SAST)',
      labelEn: 'Code SAST Auditor',
      icon: Code2,
      badge: 'Semgrep',
    },
    {
      id: 'terminal',
      labelAr: 'مختبر الـ Sandbox',
      labelEn: 'Interactive Terminal',
      icon: Terminal,
      badge: 'Isolated',
    },
    {
      id: 'toolbox',
      labelAr: 'صندوق الأدوات',
      labelEn: 'Cyber Toolbox',
      icon: Wrench,
    },
    {
      id: 'knowledge',
      labelAr: 'قاعدة المعرفة و MITRE',
      labelEn: 'OWASP & MITRE',
      icon: BookOpen,
    },
    {
      id: 'ctf',
      labelAr: 'مختبرات الـ CTF والـ Labs',
      labelEn: 'CTF & Cyber Labs',
      icon: Flag,
    },
    {
      id: 'report',
      labelAr: 'منشئ التقارير التنفيذية',
      labelEn: 'Report Builder',
      icon: FileText,
    },
  ];

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-teal-500 to-indigo-500 p-0.5 shadow-lg shadow-cyan-500/20">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-bold text-lg text-slate-100 tracking-tight flex items-center gap-1.5">
                  <span>CYBERGUARD</span>
                  <span className="text-cyan-400 text-xs px-1.5 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-800/60 font-mono">
                    MULTI-AGENT
                  </span>
                </h1>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                {isAr ? 'منصة الأمن السيبراني متعددة الوكلاء والتحقق الآلي' : 'Enterprise Multi-Agent Cybersecurity Platform'}
              </p>
            </div>
          </div>

          {/* Navigation Tabs (Desktop) */}
          <nav className="hidden xl:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-tab-${item.id}`}
                  onClick={() => setActiveTab(item.id)}
                  className={`relative flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'text-cyan-300 bg-cyan-950/60 border border-cyan-800/60 shadow-sm shadow-cyan-950'
                      : 'text-slate-300 hover:text-slate-100 hover:bg-slate-900/60 border border-transparent'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{isAr ? item.labelAr : item.labelEn}</span>
                  {item.badge && (
                    <span className={`text-[9px] font-mono px-1 rounded ${
                      isActive ? 'bg-cyan-900/80 text-cyan-200' : 'bg-slate-800 text-slate-400'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                  {isActive && (
                    <span className="absolute -bottom-[17px] left-1/2 -translate-x-1/2 w-8 h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent" />
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right actions: Language toggle & Status */}
          <div className="flex items-center gap-3">
            <button
              id="lang-toggle-btn"
              onClick={() => setLanguage(isAr ? 'en' : 'ar')}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-900/80 hover:bg-slate-800 text-slate-200 text-xs font-medium transition-colors"
              title={isAr ? 'Switch to English' : 'التحويل للعربية'}
            >
              <Globe className="w-3.5 h-3.5 text-cyan-400" />
              <span>{isAr ? 'English' : 'العربية'}</span>
            </button>

            <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-950/50 border border-emerald-800/40 text-emerald-300 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>12 AGENTS ACTIVE</span>
            </div>
          </div>
        </div>

        {/* Sub-Navigation (Scrollable for tablet/mobile/narrow) */}
        <div className="xl:hidden flex items-center gap-1 overflow-x-auto py-2 border-t border-slate-800/60 no-scrollbar">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium ${
                  isActive
                    ? 'text-cyan-300 bg-cyan-950/80 border border-cyan-800/60'
                    : 'text-slate-400 hover:text-slate-200 bg-slate-900/40'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{isAr ? item.labelAr : item.labelEn}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
