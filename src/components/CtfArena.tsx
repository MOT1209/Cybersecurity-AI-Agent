import React, { useState } from 'react';
import { 
  Flag, 
  HelpCircle, 
  CheckCircle2, 
  AlertCircle, 
  Bot, 
  Unlock,
  KeyRound,
  Trophy
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { CTF_SCENARIOS } from '../data/cyberData';
import { CTFScenario } from '../types';

interface CtfArenaProps {
  language: 'ar' | 'en';
  onAskAgentAboutChallenge: (scenario: CTFScenario) => void;
}

export const CtfArena: React.FC<CtfArenaProps> = ({ language, onAskAgentAboutChallenge }) => {
  const isAr = language === 'ar';
  const [selectedChallengeId, setSelectedChallengeId] = useState<string>(CTF_SCENARIOS[0].id);
  const [flagInputs, setFlagInputs] = useState<Record<string, string>>({});
  const [solvedChallenges, setSolvedChallenges] = useState<Record<string, boolean>>({});
  const [revealedHints, setRevealedHints] = useState<Record<string, number>>({});
  const [errorStatus, setErrorStatus] = useState<Record<string, string>>({});

  const activeScenario = CTF_SCENARIOS.find((s) => s.id === selectedChallengeId) || CTF_SCENARIOS[0];

  const handleRevealNextHint = (id: string, totalHints: number) => {
    const current = revealedHints[id] || 0;
    if (current < totalHints) {
      setRevealedHints((prev) => ({ ...prev, [id]: current + 1 }));
    }
  };

  const handleVerifyFlag = (scenario: CTFScenario) => {
    const input = (flagInputs[scenario.id] || '').trim();
    if (!input) return;

    if (input === scenario.flag) {
      setSolvedChallenges((prev) => ({ ...prev, [scenario.id]: true }));
      setErrorStatus((prev) => ({ ...prev, [scenario.id]: '' }));
      // Trigger festive confetti
      confetti({
        particleCount: 80,
        spread: 70,
        origin: { y: 0.6 },
      });
    } else {
      setErrorStatus((prev) => ({
        ...prev,
        [scenario.id]: isAr ? 'العلم (Flag) غير صحيح، راجع تلميحات السيناريو وحاول مجدداً!' : 'Incorrect Flag, review hints and try again!',
      }));
    }
  };

  const solvedCount = Object.values(solvedChallenges).filter(Boolean).length;

  return (
    <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col gap-5">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-slate-900/90 border border-slate-800 rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-amber-950/80 border border-amber-800/60 text-amber-400">
            <Flag className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span>{isAr ? 'ميدان تحديات الـ CTF التعليمية' : 'Interactive CTF Practice Arena'}</span>
            </h2>
            <p className="text-xs text-slate-400">
              {isAr
                ? 'طبق مهاراتك في اختبار الاختراق وفك الشيفرات عبر سيناريوهات عملية، مع تلميحات وإرشاد من وكيل الـ AI.'
                : 'Solve hands-on security and cryptography challenges with progressive hints and AI mentor guidance.'}
            </p>
          </div>
        </div>

        {/* Solved Score Badge */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-950 border border-amber-900/40">
          <Trophy className="w-4 h-4 text-amber-400" />
          <span className="text-xs text-slate-300 font-medium">{isAr ? 'التحديات المنجزة:' : 'Solved:'}</span>
          <span className="text-sm font-bold font-mono text-amber-400">
            {solvedCount} / {CTF_SCENARIOS.length}
          </span>
        </div>
      </div>

      {/* Main CTF Arena Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Challenge list on Left */}
        <div className="lg:col-span-4 flex flex-col gap-2.5">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-1">
            {isAr ? 'قائمة التحديات:' : 'Available Challenges:'}
          </span>

          {CTF_SCENARIOS.map((scenario) => {
            const isSelected = scenario.id === selectedChallengeId;
            const isSolved = solvedChallenges[scenario.id];
            return (
              <button
                key={scenario.id}
                onClick={() => setSelectedChallengeId(scenario.id)}
                className={`flex flex-col text-start p-3.5 rounded-xl border transition-all ${
                  isSelected
                    ? 'bg-slate-800 border-amber-500/80 shadow-md shadow-amber-950/40'
                    : 'bg-slate-900/60 border-slate-800/80 hover:bg-slate-800/60 text-slate-300'
                }`}
              >
                <div className="flex items-center justify-between gap-2 w-full mb-1">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-cyan-400 border border-slate-800">
                      {scenario.category}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        scenario.difficulty === 'Easy'
                          ? 'text-emerald-400 bg-emerald-950/40'
                          : scenario.difficulty === 'Medium'
                          ? 'text-amber-400 bg-amber-950/40'
                          : 'text-red-400 bg-red-950/40'
                      }`}
                    >
                      {scenario.difficulty}
                    </span>
                  </div>

                  {isSolved && (
                    <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-semibold">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{isAr ? 'محلول' : 'Solved'}</span>
                    </span>
                  )}
                </div>

                <span className="text-xs font-bold text-slate-100 mt-1">
                  {isAr ? scenario.titleAr : scenario.titleEn}
                </span>
              </button>
            );
          })}
        </div>

        {/* Challenge details on Right */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                  {activeScenario.category}
                </span>
                <span className="text-xs font-mono text-amber-400 bg-amber-950 px-2 py-0.5 rounded border border-amber-800">
                  {activeScenario.difficulty}
                </span>
              </div>
              <h3 className="text-base font-bold text-slate-100 mt-2">
                {isAr ? activeScenario.titleAr : activeScenario.titleEn}
              </h3>
            </div>

            <button
              onClick={() => onAskAgentAboutChallenge(activeScenario)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-300 hover:bg-cyan-900 text-xs font-medium transition-colors"
            >
              <Bot className="w-4 h-4 text-cyan-400" />
              <span>{isAr ? 'طلب مساعدة وكيل الـ AI' : 'Ask AI Mentor'}</span>
            </button>
          </div>

          <div className="text-xs text-slate-300">
            <p className="leading-relaxed">{isAr ? activeScenario.descriptionAr : activeScenario.descriptionEn}</p>
          </div>

          {/* Scenario Sandbox Details Box */}
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200">
            <span className="text-[10px] text-slate-500 uppercase font-semibold block mb-1">
              {isAr ? 'بيانات وسيناريو التحدي:' : 'Scenario Data:'}
            </span>
            <pre className="whitespace-pre-wrap leading-relaxed text-cyan-300">{activeScenario.scenarioDetails}</pre>
          </div>

          {/* Hints Section */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
                <span>{isAr ? 'التلميحات التدريجية (Hints):' : 'Progressive Hints:'}</span>
              </span>

              {(revealedHints[activeScenario.id] || 0) < activeScenario.hints.length && (
                <button
                  onClick={() => handleRevealNextHint(activeScenario.id, activeScenario.hints.length)}
                  className="flex items-center gap-1 text-[11px] text-amber-400 hover:text-amber-300 bg-amber-950/40 border border-amber-900/60 px-2 py-1 rounded"
                >
                  <Unlock className="w-3 h-3" />
                  <span>{isAr ? 'كشف التلميح التالي' : 'Unlock Next Hint'}</span>
                </button>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              {activeScenario.hints.slice(0, revealedHints[activeScenario.id] || 0).map((hint, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-900/40 text-xs text-amber-200 flex items-start gap-2">
                  <span className="font-bold text-amber-400 font-mono">#{idx + 1}:</span>
                  <span className="leading-relaxed">{hint}</span>
                </div>
              ))}
              {(revealedHints[activeScenario.id] || 0) === 0 && (
                <div className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-500 italic">
                  {isAr ? 'لم يتم فتح أي تلميح بعد. حاول حل التحدي بنفسك أولاً!' : 'No hints unlocked yet. Try solving it on your own first!'}
                </div>
              )}
            </div>
          </div>

          {/* Flag Submission Bar */}
          <div className="mt-2 p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
                <span>{isAr ? 'إرسال العلم (Submit Flag):' : 'Submit Flag:'}</span>
              </label>
              {solvedChallenges[activeScenario.id] && (
                <span className="text-xs text-emerald-400 font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{isAr ? 'تم الحل بنجاح!' : 'Challenge Solved!'}</span>
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              <input
                type="text"
                value={flagInputs[activeScenario.id] || ''}
                onChange={(e) => setFlagInputs({ ...flagInputs, [activeScenario.id]: e.target.value })}
                onKeyDown={(e) => e.key === 'Enter' && handleVerifyFlag(activeScenario)}
                placeholder="FLAG{...}"
                disabled={solvedChallenges[activeScenario.id]}
                className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-700 disabled:opacity-50"
              />
              <button
                onClick={() => handleVerifyFlag(activeScenario)}
                disabled={solvedChallenges[activeScenario.id] || !(flagInputs[activeScenario.id] || '').trim()}
                className="px-4 py-2 rounded-lg bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-slate-950 font-bold text-xs shadow-md shadow-amber-950 disabled:opacity-40"
              >
                {isAr ? 'تحقق' : 'Submit'}
              </button>
            </div>

            {errorStatus[activeScenario.id] && (
              <div className="text-xs text-rose-400 flex items-center gap-1.5 mt-1">
                <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                <span>{errorStatus[activeScenario.id]}</span>
              </div>
            )}

            {solvedChallenges[activeScenario.id] && (
              <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/60 text-xs text-emerald-200 mt-2">
                <span className="font-bold text-emerald-400 block mb-1">{isAr ? 'شرح الحل التقني:' : 'Solution Walkthrough:'}</span>
                <p className="leading-relaxed text-[11px]">{activeScenario.solutionExplanation}</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
