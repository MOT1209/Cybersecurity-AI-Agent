import React, { useState, useRef, useEffect } from 'react';
import { apiFetch } from '../lib/api';
import { 
  Send, 
  Bot, 
  User, 
  Trash2, 
  Copy, 
  Check, 
  GraduationCap, 
  ShieldCheck, 
  Crosshair, 
  Activity, 
  Search,
  Download,
  AlertCircle,
  Lightbulb,
  Cpu
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { AgentPersona, ChatMessage, CTFScenario } from '../types';
import { SUGGESTED_QUESTIONS } from '../data/cyberData';
import { useCopy } from '../lib/useCopy';

interface AgentWorkspaceProps {
  language: 'ar' | 'en';
  /** Scenario handed over from the CTF arena via "ask the mentor". */
  pendingChallenge?: CTFScenario | null;
  /** Called once the scenario has been turned into a question. */
  onChallengeConsumed?: () => void;
}

export const AgentWorkspace: React.FC<AgentWorkspaceProps> = ({
  language,
  pendingChallenge,
  onChallengeConsumed,
}) => {
  const isAr = language === 'ar';
  const [persona, setPersona] = useState<AgentPersona>('tutor');
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    return [
      {
        id: 'welcome-msg',
        role: 'assistant',
        persona: 'tutor',
        content: isAr
          ? `مرحباً بك! أنا **CyberAgent AI**، مساعدك الذكي المتخصص في **الأمن السيبراني والاختراق الأخلاقي (Ethical Hacking & Cybersecurity)**. 🛡️

أنا هنا لمساعدتك في رحلة تعلمك واحترافك خطوة بخطوة:
- 📖 **شرح المفاهيم**: من أساسيات الشبكات والتشفير إلى أعقد هجمات الويب والأنظمة.
- 🛠️ **تحليل الأدوات**: فهم أدوات مثل Nmap, Burp Suite, Wireshark, Metasploit, SQLMap وكيفية عملها.
- 🔍 **فحص الثغرات**: مراجعة الأكواد البرمجية والتكوينات وتقديم كود الترقيع الآمن.
- 🎯 **حلول ومسارات CTF**: تلميحات وتدريب تفاعلي لتحديات القرصنة الأخلاقية.
- 📑 **منهجيات الفحص**: تطبيق معايير PTES, OWASP WSTG, و MITRE ATT&CK.

اختر تخصص الوكيل الذي تريده من الأعلى، أو اسألني أي سؤال مباشرة!`
          : `Welcome! I am **CyberAgent AI**, your dedicated assistant for **Cybersecurity & Ethical Hacking**. 🛡️

I am here to guide your learning and professional journey:
- 📖 **Core Concepts**: Network defense, cryptography, OWASP Top 10, binary exploitation, and cloud security.
- 🛠️ **Tool Methodologies**: Deep insights into Nmap, Wireshark, Burp Suite, SQLMap, and Metasploit.
- 🔍 **Vulnerability Auditing**: Code review, CWE mapping, and remediation patches.
- 🎯 **CTF Coaching**: Hints and walk-through strategies for capture-the-flag scenarios.

Select an agent persona above or ask anything to get started!`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ];
  });

  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const { copy, isCopied } = useCopy();
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  // A challenge arriving from the CTF arena is turned into a real question so
  // the mentor answers with the scenario in context, rather than the user
  // landing on an empty chat and having to retype it.
  useEffect(() => {
    if (!pendingChallenge || loading) return;

    const title = isAr ? pendingChallenge.titleAr : pendingChallenge.titleEn;
    const question = isAr
      ? `أحتاج إرشادًا في تحدي CTF التالي — لا تعطني العلم مباشرة، بل وجّهني خطوة بخطوة.

**التحدي:** ${title}
**التصنيف:** ${pendingChallenge.category} · **الصعوبة:** ${pendingChallenge.difficulty}

${pendingChallenge.scenarioDetails}`
      : `I need guidance on the following CTF challenge. Do not give me the flag outright — walk me through it step by step.

**Challenge:** ${title}
**Category:** ${pendingChallenge.category} · **Difficulty:** ${pendingChallenge.difficulty}

${pendingChallenge.scenarioDetails}`;

    setPersona('tutor');
    onChallengeConsumed?.();
    void handleSendMessage(question);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingChallenge]);

  const personas = [
    {
      id: 'tutor' as AgentPersona,
      nameAr: 'المرشد والمعلم الأمني',
      nameEn: 'Cyber Security Mentor',
      descAr: 'شرح المفاهيم، خوارزميات التشفير، الأدوات، والتوجيه الأكاديمي',
      descEn: 'Foundational concepts, cryptography, tools, and learning paths',
      icon: GraduationCap,
      color: 'from-cyan-500 to-blue-600',
      activeBorder: 'border-cyan-500',
    },
    {
      id: 'auditor' as AgentPersona,
      nameAr: 'مدقق الأكواد والتكوين (SAST)',
      nameEn: 'AppSec Code Auditor',
      descAr: 'مراجعة الأكواد، كشف الثغرات، وتوليد كود الترقيع المحمي',
      descEn: 'Static code analysis, OWASP/CWE breakdown, secure patches',
      icon: ShieldCheck,
      color: 'from-emerald-500 to-teal-600',
      activeBorder: 'border-emerald-500',
    },
    {
      id: 'pentest_coach' as AgentPersona,
      nameAr: 'مدرب اختبار الاختراق (PTES)',
      nameEn: 'Ethical Pentest Coach',
      descAr: 'منهجيات جمع المعلومات، الاستغلال الأخلاقي المصرح، والتوثيق',
      descEn: 'Recon, enumeration, methodology workflows, and PoC analysis',
      icon: Crosshair,
      color: 'from-amber-500 to-orange-600',
      activeBorder: 'border-amber-500',
    },
    {
      id: 'soc_analyst' as AgentPersona,
      nameAr: 'محلل SOC والاستجابة',
      nameEn: 'SOC & Incident Analyst',
      descAr: 'تحليل السجلات (Logs)، مؤشرات الاختراق IoCs، وقواعد الكشف',
      descEn: 'Log triage, IoC detection, Sigma/Yara rules, containment',
      icon: Activity,
      color: 'from-purple-500 to-indigo-600',
      activeBorder: 'border-purple-500',
    },
    {
      id: 'cve_intel' as AgentPersona,
      nameAr: 'استخبارات الثغرات (CVE)',
      nameEn: 'Threat & CVE Intel',
      descAr: 'تحليل أحدث الثغرات المنشورة ومصفوفة MITRE ATT&CK',
      descEn: 'Vulnerability threat intelligence, CVE breakdowns, patches',
      icon: Search,
      color: 'from-rose-500 to-pink-600',
      activeBorder: 'border-rose-500',
    },
  ];

  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend || input).trim();
    if (!query || loading) return;

    setErrorMsg(null);
    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const updatedMessages = [...messages, userMessage];
    setMessages(updatedMessages);
    setInput('');
    setLoading(true);

    try {
      // Send conversation history to backend Express endpoint
      const payloadMessages = updatedMessages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const res = await apiFetch('/api/gemini/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: payloadMessages,
          role: persona,
          language: language,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP error! status: ${res.status}`);
      }

      const data = await res.json();

      const botMessage: ChatMessage = {
        id: `bot-${Date.now()}`,
        role: 'assistant',
        persona: persona,
        content: data.reply || (isAr ? 'عذراً، لم أستطع توليد الإجابة.' : 'Sorry, no response generated.'),
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, botMessage]);
    } catch (err: any) {
      console.error('Chat error:', err);
      setErrorMsg(err?.message || (isAr ? 'فشل الاتصال بوكيل الذكاء الاصطناعي' : 'Failed to connect to AI Agent'));
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (id: string, text: string) => {
    void copy(text, id);
  };

  const handleClearChat = () => {
    setMessages([]);
    setErrorMsg(null);
  };

  const handleExportChat = () => {
    const transcript = messages
      .map((m) => `[${m.timestamp}] ${m.role === 'user' ? 'USER' : 'CYBERAGENT (' + (m.persona || 'AI') + ')'}:\n${m.content}\n\n---\n`)
      .join('\n');
    
    const blob = new Blob([transcript], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberAgent-Session-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const activePersonaObj = personas.find((p) => p.id === persona);

  return (
    <div className="flex flex-col h-[calc(100vh-4.5rem)] max-w-7xl mx-auto px-2 sm:px-4 py-3 gap-3">
      {/* Persona Selection Strip */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-2.5 backdrop-blur-sm">
        <div className="flex items-center justify-between mb-2 px-1">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              {isAr ? 'تخصص الوكيل الذكي (AI Persona):' : 'Select AI Agent Specialization:'}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleExportChat}
              disabled={messages.length === 0}
              className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-800/60 hover:bg-slate-800 disabled:opacity-40 transition-colors"
              title={isAr ? 'تصدير المحادثة بتنسيق Markdown' : 'Export transcript'}
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{isAr ? 'تصدير' : 'Export'}</span>
            </button>
            <button
              onClick={handleClearChat}
              disabled={messages.length === 0}
              className="flex items-center gap-1 text-xs text-rose-400 hover:text-rose-300 px-2 py-1 rounded bg-rose-950/30 hover:bg-rose-950/60 border border-rose-900/40 disabled:opacity-40 transition-colors"
              title={isAr ? 'مسح المحادثة' : 'Clear chat'}
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{isAr ? 'مسح' : 'Clear'}</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
          {personas.map((p) => {
            const Icon = p.icon;
            const isSelected = persona === p.id;
            return (
              <button
                key={p.id}
                id={`persona-btn-${p.id}`}
                onClick={() => setPersona(p.id)}
                className={`flex flex-col items-start text-start p-2 rounded-lg border transition-all ${
                  isSelected
                    ? `bg-slate-800/90 ${p.activeBorder} shadow-md shadow-cyan-950/50`
                    : 'bg-slate-950/40 border-slate-800/80 hover:bg-slate-800/50 text-slate-400'
                }`}
              >
                <div className="flex items-center gap-1.5 w-full mb-1">
                  <div className={`p-1 rounded-md bg-gradient-to-br ${p.color} text-white shadow-sm`}>
                    <Icon className="w-3.5 h-3.5" />
                  </div>
                  <span className={`text-xs font-semibold truncate ${isSelected ? 'text-slate-100' : 'text-slate-300'}`}>
                    {isAr ? p.nameAr : p.nameEn}
                  </span>
                </div>
                <span className="text-[10px] text-slate-400 line-clamp-1 leading-tight">
                  {isAr ? p.descAr : p.descEn}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Messages Container */}
      <div className="flex-1 overflow-y-auto bg-slate-900/50 border border-slate-800/80 rounded-xl p-3 sm:p-5 flex flex-col gap-4">
        {messages.map((msg) => {
          const isBot = msg.role === 'assistant';
          return (
            <div
              key={msg.id}
              className={`flex gap-3 max-w-4xl ${isBot ? 'self-start w-full' : 'self-end max-w-[85%] sm:max-w-[75%]'}`}
            >
              {isBot && (
                <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-teal-400 p-0.5 mt-0.5 shadow-md shadow-cyan-900/30">
                  <div className="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
                    <Bot className="w-4 h-4 text-cyan-400" />
                  </div>
                </div>
              )}

              <div
                className={`relative group rounded-2xl p-4 shadow-sm ${
                  isBot
                    ? 'bg-slate-900 border border-slate-800 text-slate-200 w-full'
                    : 'bg-gradient-to-r from-cyan-600 to-teal-600 text-white shadow-cyan-900/20'
                }`}
              >
                {isBot && (
                  <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-[11px] text-slate-400 font-mono">
                    <div className="flex items-center gap-1.5">
                      <span className="text-cyan-400 font-semibold">CyberAgent</span>
                      <span className="text-slate-600">•</span>
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                        {msg.persona ? msg.persona.toUpperCase() : 'AI'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span>{msg.timestamp}</span>
                      <button
                        onClick={() => handleCopy(msg.id, msg.content)}
                        className="opacity-0 group-hover:opacity-100 hover:text-cyan-400 transition-opacity p-1"
                        title={isAr ? 'نسخ النص' : 'Copy'}
                      >
                        {isCopied(msg.id) ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </div>
                )}

                <div className="prose prose-invert max-w-none text-sm leading-relaxed overflow-x-auto">
                  <ReactMarkdown
                    components={{
                      code({ className, children, ...props }) {
                        const match = /language-(\w+)/.exec(className || '');
                        return match ? (
                          <div className="my-2 rounded-lg bg-slate-950 border border-slate-800 overflow-hidden font-mono text-xs">
                            <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900 border-b border-slate-800 text-[11px] text-slate-400">
                              <span>{match[1]}</span>
                              <button
                                onClick={() => void copy(String(children).replace(/\n$/, ''), 'inline-code')}
                                className="hover:text-cyan-400 flex items-center gap-1 text-[10px]"
                              >
                                <Copy className="w-3 h-3" />
                                <span>{isAr ? 'نسخ الكود' : 'Copy'}</span>
                              </button>
                            </div>
                            <pre className="p-3 overflow-x-auto text-slate-200">
                              <code className={className} {...props}>
                                {children}
                              </code>
                            </pre>
                          </div>
                        ) : (
                          <code className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-xs" {...props}>
                            {children}
                          </code>
                        );
                      },
                    }}
                  >
                    {msg.content}
                  </ReactMarkdown>
                </div>

                {!isBot && (
                  <div className="text-[10px] text-cyan-100/80 text-end mt-1">
                    {msg.timestamp}
                  </div>
                )}
              </div>

              {!isBot && (
                <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 mt-0.5">
                  <User className="w-4 h-4" />
                </div>
              )}
            </div>
          );
        })}

        {loading && (
          <div className="flex gap-3 max-w-4xl self-start w-full">
            <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-teal-400 p-0.5 mt-0.5">
              <div className="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
                <Bot className="w-4 h-4 text-cyan-400 animate-pulse" />
              </div>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 text-slate-300 text-sm flex items-center gap-3">
              <div className="flex gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '0ms' }} />
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '150ms' }} />
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
              <span className="text-xs text-slate-400 font-mono">
                {isAr ? `الوكيل [${activePersonaObj?.nameAr}] يقوم بالتحليل المعمق والتفكير...` : `Agent [${activePersonaObj?.nameEn}] is analyzing and formulating response...`}
              </span>
            </div>
          </div>
        )}

        {errorMsg && (
          <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0 text-rose-400" />
            <span>{errorMsg}</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Prompt Pills (Quick Questions) */}
      <div className="flex items-center gap-1.5 overflow-x-auto py-1 no-scrollbar">
        <div className="flex items-center gap-1 text-[11px] text-slate-400 font-medium whitespace-nowrap pl-1">
          <Lightbulb className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
          <span>{isAr ? 'أسئلة مقترحة:' : 'Suggestions:'}</span>
        </div>
        {SUGGESTED_QUESTIONS.slice(0, 4).map((q, idx) => (
          <button
            key={idx}
            onClick={() => handleSendMessage(q)}
            className="flex-shrink-0 text-xs px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 hover:border-cyan-800/80 hover:bg-slate-800 text-slate-300 hover:text-cyan-200 transition-colors"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage();
        }}
        className="relative bg-slate-900/90 border border-slate-800 rounded-xl p-2 flex items-center gap-2 shadow-lg shadow-black/40 focus-within:border-cyan-700/80"
      >
        <textarea
          id="chat-user-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              handleSendMessage();
            }
          }}
          placeholder={
            isAr
              ? `اسأل وكيل الأمن السيبراني أي سؤال أو اطلب فحص أمر أو ثغرة... (Enter للإرسال)`
              : `Ask the CyberAgent assistant anything about ethical hacking, tools, code... (Enter to send)`
          }
          rows={1}
          className="flex-1 bg-transparent text-slate-100 placeholder-slate-500 text-sm focus:outline-none resize-none px-2 py-1 max-h-28 overflow-y-auto"
        />
        <button
          type="submit"
          id="chat-send-btn"
          disabled={!input.trim() || loading}
          className="flex-shrink-0 flex items-center justify-center w-9 h-9 rounded-lg bg-gradient-to-r from-cyan-500 to-teal-500 hover:from-cyan-400 hover:to-teal-400 text-slate-950 font-bold disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-md shadow-cyan-900/30"
          title={isAr ? 'إرسال' : 'Send'}
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
};
