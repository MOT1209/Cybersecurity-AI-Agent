import React, { useState, useRef, useEffect } from 'react';
import { apiFetch } from '../lib/api';
import { 
  Terminal as TerminalIcon, 
  Play, 
  Trash2, 
  Sparkles, 
  HelpCircle, 
  CheckCircle2, 
  AlertCircle,
  Server,
  ArrowRight
} from 'lucide-react';
import { TerminalEntry } from '../types';

interface InteractiveTerminalLabProps {
  language: 'ar' | 'en';
}

export const InteractiveTerminalLab: React.FC<InteractiveTerminalLabProps> = ({ language }) => {
  const isAr = language === 'ar';
  const [targetHost, setTargetHost] = useState<string>('192.168.1.50 (Simulated Lab Box)');
  const [commandInput, setCommandInput] = useState<string>('nmap -sV -sC 192.168.1.50');
  const [loading, setLoading] = useState<boolean>(false);
  const [history, setHistory] = useState<TerminalEntry[]>(() => [
    {
      id: 'init-1',
      command: 'uname -a',
      output: 'Linux cyberagent-lab 6.5.0-kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.5.6-1kali1 x86_64 GNU/Linux',
      explanation: isAr ? 'معلومات نظام التشغيل والنواة في بيئة المختبر الافتراضية.' : 'Host kernel and architecture information in sandbox lab.',
      findings: [isAr ? 'نظام كالي لينكس تعليمي معزول وآمن 100%' : 'Isolated educational Kali Linux sandbox'],
      suggestedNextCommands: ['nmap -sV -sC 192.168.1.50', 'whois target.local'],
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const [cmdHistoryList, setCmdHistoryList] = useState<string[]>(['uname -a', 'nmap -sV -sC 192.168.1.50']);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history, loading]);

  const presetCommands = [
    { label: 'Nmap Port Scan', cmd: 'nmap -sV -sC 192.168.1.50' },
    { label: 'HTTP Headers Recon', cmd: 'curl -I -L https://target.local/admin' },
    { label: 'Nikto Web Scan', cmd: 'nikto -h http://192.168.1.50' },
    { label: 'SQLMap Enumeration', cmd: 'sqlmap -u "http://target.local/login.php?id=1" --dbs --batch' },
    { label: 'Hash Identifier', cmd: 'hashid "5f4dcc3b5aa765d61d8327deb882cf99"' },
    { label: 'DNS Recon (Dig)', cmd: 'dig target.local ANY +noall +answer' },
    { label: 'Linux SUID Finder', cmd: 'find / -perm -u=s -type f 2>/dev/null' },
    { label: 'Active Network Sockets', cmd: 'ss -tulnp' },
  ];

  const handleRunCommand = async (customCmd?: string) => {
    const cmd = (customCmd || commandInput).trim();
    if (!cmd || loading) return;

    if (cmd.toLowerCase() === 'clear') {
      setHistory([]);
      setCommandInput('');
      return;
    }

    setLoading(true);
    setCmdHistoryList((prev) => [...prev, cmd]);
    setHistoryIndex(-1);
    setCommandInput('');

    try {
      const res = await apiFetch('/api/gemini/simulate-cmd', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: cmd,
          target: targetHost,
          previousOutputs: history.slice(-2).map((h) => h.command),
        }),
      });

      if (!res.ok) {
        throw new Error(`HTTP error ${res.status}`);
      }

      const data = await res.json();

      const newEntry: TerminalEntry = {
        id: `term-${Date.now()}`,
        command: cmd,
        output: data.output || 'Command executed successfully.',
        explanation: data.explanation,
        findings: data.findings || [],
        suggestedNextCommands: data.suggestedNextCommands || [],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setHistory((prev) => [...prev, newEntry]);
    } catch (err: any) {
      console.error('Command simulation error:', err);
      const errorEntry: TerminalEntry = {
        id: `term-${Date.now()}`,
        command: cmd,
        output: `bash: ${cmd}: failed to simulate command execution (${err?.message || 'Server error'})`,
        isError: true,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setHistory((prev) => [...prev, errorEntry]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleRunCommand();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (cmdHistoryList.length === 0) return;
      const nextIndex = historyIndex === -1 ? cmdHistoryList.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIndex);
      setCommandInput(cmdHistoryList[nextIndex]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex === -1) return;
      const nextIndex = historyIndex + 1;
      if (nextIndex >= cmdHistoryList.length) {
        setHistoryIndex(-1);
        setCommandInput('');
      } else {
        setHistoryIndex(nextIndex);
        setCommandInput(cmdHistoryList[nextIndex]);
      }
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col gap-4">
      {/* Top Controls Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-slate-900/90 border border-slate-800 rounded-xl p-3.5">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800/60 text-cyan-400">
            <TerminalIcon className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>{isAr ? 'مختبر سطر الأوامر والأدوات المحاكي' : 'Simulated Cyber Lab Terminal'}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-400 font-mono">
                SAFE SANDBOX
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'بيئة تدريبية تفاعلية لتجربة أدوات فحص الشبكات والتطبيقات وتحليل مخرجاتها بدعم الذكاء الاصطناعي.'
                : 'Interactive safe sandbox to execute recon and vulnerability tools with real-time AI breakdown.'}
            </p>
          </div>
        </div>

        {/* Target Lab IP configuration */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400 text-[11px]">{isAr ? 'الهدف:' : 'Target:'}</span>
            <input
              type="text"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              className="bg-transparent font-mono text-cyan-300 font-semibold focus:outline-none text-xs w-48"
              placeholder="e.g. 192.168.1.50"
            />
          </div>
          <button
            onClick={() => setHistory([])}
            className="p-2 rounded-lg bg-slate-950 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-rose-400 transition-colors"
            title={isAr ? 'مسح مخرجات الـ Terminal' : 'Clear Terminal'}
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Preset Quick Commands Bar */}
      <div className="flex items-center gap-2 overflow-x-auto py-1 no-scrollbar">
        <span className="text-xs text-slate-400 font-medium whitespace-nowrap pl-1">
          {isAr ? 'أوامر سريعة:' : 'Quick Presets:'}
        </span>
        {presetCommands.map((preset, idx) => (
          <button
            key={idx}
            onClick={() => {
              setCommandInput(preset.cmd);
              handleRunCommand(preset.cmd);
            }}
            disabled={loading}
            className="flex-shrink-0 text-xs px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-700 hover:bg-slate-800 text-slate-300 hover:text-cyan-200 transition-all font-mono"
          >
            {preset.label}
          </button>
        ))}
      </div>

      {/* Terminal Screen & AI Analytics Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Terminal Screen (Kali Style) */}
        <div className="lg:col-span-8 bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col min-h-[500px]">
          {/* Terminal Window Topbar */}
          <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block" />
                <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
                <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
              </div>
              <span className="text-slate-300 font-semibold ml-2">cyberagent@lab-box: ~</span>
            </div>
            <div className="text-[11px] text-slate-500">
              bash • UTF-8 • Virtual Sandbox
            </div>
          </div>

          {/* Terminal Logs & Output */}
          <div className="flex-1 p-4 overflow-y-auto font-mono text-xs text-slate-200 space-y-4 max-h-[480px]">
            {history.map((entry) => (
              <div key={entry.id} className="space-y-1.5">
                {/* Command Line Prompt */}
                <div className="flex items-center gap-2 text-cyan-400">
                  <span className="text-emerald-400 font-bold">┌──(cyberagent㉿lab)-[~]</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-bold">└─$</span>
                  <span className="text-slate-100 font-bold">{entry.command}</span>
                  <span className="text-[10px] text-slate-600 ml-auto">{entry.timestamp}</span>
                </div>

                {/* Output Pre */}
                <div
                  className={`p-3 rounded-lg text-xs leading-relaxed overflow-x-auto whitespace-pre-wrap ${
                    entry.isError
                      ? 'bg-rose-950/30 text-rose-300 border border-rose-900/40'
                      : 'bg-slate-900/60 text-slate-300 border border-slate-800/60'
                  }`}
                >
                  {entry.output}
                </div>
              </div>
            ))}

            {loading && (
              <div className="space-y-1.5 animate-pulse">
                <div className="flex items-center gap-2 text-cyan-400">
                  <span className="text-emerald-400 font-bold">┌──(cyberagent㉿lab)-[~]</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-bold">└─$</span>
                  <span className="text-cyan-300">{commandInput}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-900/60 text-cyan-400/80 text-xs flex items-center gap-2 font-mono">
                  <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                  <span>{isAr ? 'جاري تنفيذ الأمر وتحليل حركة الشبكة في بيئة المختبر...' : 'Executing command and analyzing virtual network output...'}</span>
                </div>
              </div>
            )}

            <div ref={terminalEndRef} />
          </div>

          {/* Interactive Command Input Line */}
          <div className="p-3 bg-slate-900/90 border-t border-slate-800 flex items-center gap-2 font-mono text-xs">
            <span className="text-emerald-400 font-bold flex-shrink-0">cyberagent@lab:~$</span>
            <input
              ref={inputRef}
              id="terminal-cmd-input"
              type="text"
              value={commandInput}
              onChange={(e) => setCommandInput(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={loading}
              placeholder={isAr ? 'اكتب أمر فحص أمني (مثل: nmap, whois, curl, sqlmap) واضغط Enter' : 'Type a security command and press Enter'}
              className="flex-1 bg-transparent text-slate-100 placeholder-slate-600 focus:outline-none selection:bg-cyan-500/30"
              autoFocus
            />
            <button
              onClick={() => handleRunCommand()}
              disabled={!commandInput.trim() || loading}
              className="px-3 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs disabled:opacity-40 transition-colors flex items-center gap-1"
            >
              <span>{isAr ? 'تنفيذ' : 'Run'}</span>
              <Play className="w-3 h-3 fill-slate-950" />
            </button>
          </div>
        </div>

        {/* AI Real-Time Findings & Explanation Column */}
        <div className="lg:col-span-4 flex flex-col gap-3">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col gap-3 h-full">
            <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                {isAr ? 'التحليل الذكي للنتائج (AI Analysis)' : 'AI Live Output Intelligence'}
              </h3>
            </div>

            {history.length > 0 && history[history.length - 1]?.explanation ? (
              <div className="flex flex-col gap-3 text-xs overflow-y-auto max-h-[440px]">
                {/* Active Command Info */}
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300">
                  <span className="text-slate-400">{isAr ? 'آخر أمر محلل:' : 'Last Command:'} </span>
                  <span className="font-bold">{history[history.length - 1].command}</span>
                </div>

                {/* Explanation */}
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <h4 className="font-semibold text-slate-200 mb-1 flex items-center gap-1.5">
                    <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{isAr ? 'شرح المخرجات والأثر الأمني:' : 'What This Output Means:'}</span>
                  </h4>
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    {history[history.length - 1].explanation}
                  </p>
                </div>

                {/* Detected Findings */}
                {history[history.length - 1].findings && history[history.length - 1].findings!.length > 0 && (
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <h4 className="font-semibold text-amber-300 mb-1.5 flex items-center gap-1.5">
                      <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
                      <span>{isAr ? 'المؤشرات والمنافذ المكتشفة:' : 'Discovered Indicators:'}</span>
                    </h4>
                    <ul className="space-y-1">
                      {history[history.length - 1].findings!.map((finding, idx) => (
                        <li key={idx} className="flex items-start gap-1.5 text-[11px] text-slate-300">
                          <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
                          <span>{finding}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Suggested Next Moves */}
                {history[history.length - 1].suggestedNextCommands && history[history.length - 1].suggestedNextCommands!.length > 0 && (
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <h4 className="font-semibold text-emerald-300 mb-1.5 flex items-center gap-1.5">
                      <ArrowRight className="w-3.5 h-3.5 text-emerald-400" />
                      <span>{isAr ? 'الخطوات التكتيكية التالية المقترحة:' : 'Recommended Next Tactical Steps:'}</span>
                    </h4>
                    <div className="flex flex-col gap-1.5">
                      {history[history.length - 1].suggestedNextCommands!.map((nextCmd, idx) => (
                        <button
                          key={idx}
                          onClick={() => {
                            setCommandInput(nextCmd);
                            handleRunCommand(nextCmd);
                          }}
                          className="flex items-center justify-between text-start p-2 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-800 text-[11px] font-mono text-cyan-300 transition-colors group"
                        >
                          <span className="truncate">{nextCmd}</span>
                          <Play className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 flex-shrink-0" />
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-center text-slate-500">
                <TerminalIcon className="w-10 h-10 text-slate-700 mb-2" />
                <p className="text-xs text-slate-400">
                  {isAr ? 'نفّذ أمراً في الـ Terminal لرؤية التحليل الأمني المباشر هنا.' : 'Run a command to see instant AI security triage here.'}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
