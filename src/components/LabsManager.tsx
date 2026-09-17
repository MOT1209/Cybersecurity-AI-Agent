/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vulnerable-lab targets page (§17).
 *
 * Every status on this page is read from Docker by GET /api/labs — a lab whose
 * container is gone reports STOPPED, never RUNNING by assumption, an unreachable
 * daemon reports UNKNOWN rather than masquerading as STOPPED, and the backend's
 * own `detail` string is shown verbatim rather than being reworded into
 * something more reassuring.
 *
 * The page deliberately offers no host URL. Labs run on the internal sandbox
 * network with no published ports: the address shown is reachable by the
 * agents and by nothing else, and saying so is the point.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../lib/api';
import {
  FlaskConical,
  RefreshCw,
  Play,
  Square,
  ShieldAlert,
  Network,
  Loader2,
  CircleSlash,
  CheckCircle2,
} from 'lucide-react';

interface LabsManagerProps {
  language: 'ar' | 'en';
}

type LabStatus = 'RUNNING' | 'STOPPED' | 'STARTING' | 'UNKNOWN';

/**
 * The observation behind `status`. `RUNNING` means a probe saw the app answer;
 * NOT_SERVING means one asked and did not; UNVERIFIED means no probe could run,
 * which is neither of the other two and is shown as such.
 */
interface LabReadiness {
  state: 'READY' | 'NOT_SERVING' | 'UNVERIFIED';
  observedAt?: string;
  evidence: string;
  httpStatus?: number;
  probeImage: string;
}

interface LabState {
  id: string;
  name: string;
  description: string;
  image: string;
  port: number;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  hostname: string;
  status: LabStatus;
  /** Container fact from `docker inspect`. null = could not be read. */
  containerRunning: boolean | null;
  containerId?: string;
  internalUrl: string;
  readiness: LabReadiness;
  detail: string;
  startedAt?: string;
}

const STATUS_STYLE: Record<
  LabStatus,
  { dot: string; chip: string; icon: React.ReactNode; labelAr: string; labelEn: string }
> = {
  RUNNING: {
    dot: 'bg-emerald-400',
    chip: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60',
    icon: <CheckCircle2 className="w-3.5 h-3.5" />,
    labelAr: 'قيد التشغيل',
    labelEn: 'Running',
  },
  STOPPED: {
    dot: 'bg-slate-500',
    chip: 'bg-slate-900 text-slate-400 border-slate-700',
    icon: <CircleSlash className="w-3.5 h-3.5" />,
    labelAr: 'متوقف',
    labelEn: 'Stopped',
  },
  STARTING: {
    dot: 'bg-amber-400',
    chip: 'bg-amber-950/80 text-amber-300 border-amber-700/60',
    icon: <Loader2 className="w-3.5 h-3.5 animate-spin" />,
    labelAr: 'قيد الإقلاع',
    labelEn: 'Starting',
  },
  UNKNOWN: {
    dot: 'bg-rose-400',
    chip: 'bg-rose-950/80 text-rose-300 border-rose-700/60',
    icon: <ShieldAlert className="w-3.5 h-3.5" />,
    labelAr: 'غير معروف',
    labelEn: 'Unknown',
  },
};

const READINESS_STYLE: Record<
  LabReadiness['state'],
  { className: string; labelAr: string; labelEn: string }
> = {
  READY: {
    className: 'text-emerald-300 border-emerald-800/60 bg-emerald-950/50',
    labelAr: 'مُثبَتة بفحص',
    labelEn: 'Verified by probe',
  },
  NOT_SERVING: {
    className: 'text-amber-300 border-amber-800/60 bg-amber-950/50',
    labelAr: 'لا يجيب بعد',
    labelEn: 'Not answering yet',
  },
  UNVERIFIED: {
    className: 'text-rose-300 border-rose-800/60 bg-rose-950/50',
    labelAr: 'لم تُتحقَّق',
    labelEn: 'Unverified',
  },
};

const DIFFICULTY_STYLE: Record<string, string> = {
  Beginner: 'text-emerald-300 border-emerald-800/60 bg-emerald-950/50',
  Intermediate: 'text-amber-300 border-amber-800/60 bg-amber-950/50',
  Advanced: 'text-rose-300 border-rose-800/60 bg-rose-950/50',
};

export const LabsManager: React.FC<LabsManagerProps> = ({ language }) => {
  const isAr = language === 'ar';
  const [labs, setLabs] = useState<LabState[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  /** Per-lab in-flight action, so one card's spinner never speaks for another. */
  const [busy, setBusy] = useState<Record<string, 'start' | 'stop' | undefined>>({});

  /**
   * Read every lab's state. `quiet` skips the spinner, for the background
   * refresh while a lab is still booting.
   */
  const load = useCallback(async (quiet = false) => {
    if (!quiet) setIsLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/labs');
      if (!res.ok) {
        setError(`HTTP ${res.status}`);
        return;
      }
      const data = await res.json();
      setLabs(data.labs ?? []);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      if (!quiet) setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  /**
   * A lab that is booting is a moving target: `STARTING` is `RUNNING` a few
   * seconds later. Refresh quietly until it settles, so the card shows the lab
   * becoming ready instead of leaving one state on screen forever.
   */
  const anyStarting = labs.some((l) => l.status === 'STARTING');
  useEffect(() => {
    if (!anyStarting) return;
    const timer = setInterval(() => load(true), 5000);
    return () => clearInterval(timer);
  }, [anyStarting, load]);

  /**
   * Start or stop one lab. On failure the server's own message is surfaced —
   * a 503 here means Docker is genuinely unreachable, and the page says that
   * rather than leaving a card looking like it worked.
   */
  const act = useCallback(async (id: string, action: 'start' | 'stop') => {
    setBusy((b) => ({ ...b, [id]: action }));
    setError(null);
    try {
      const res = await apiFetch(`/api/labs/${id}/${action}`, { method: 'POST' });
      const body = await res.json().catch(() => null);
      if (!res.ok) {
        setError(body?.reason || body?.message || `HTTP ${res.status}`);
        // Re-read the real state: a failed start may still have left something.
        const fresh = await apiFetch(`/api/labs/${id}`);
        if (fresh.ok) {
          const state: LabState = await fresh.json();
          setLabs((ls) => ls.map((l) => (l.id === id ? state : l)));
        }
        return;
      }
      setLabs((ls) => ls.map((l) => (l.id === id ? (body as LabState) : l)));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy((b) => ({ ...b, [id]: undefined }));
    }
  }, []);

  const running = labs.filter((l) => l.status === 'RUNNING').length;
  const starting = labs.filter((l) => l.status === 'STARTING').length;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      <div className="bg-slate-900/90 border border-cyan-500/20 rounded-2xl p-6 backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <FlaskConical className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100">
                {isAr ? 'مختبرات الأهداف المعزولة' : 'Isolated Lab Targets'}
              </h2>
              <p className="text-sm text-slate-400 mt-1 max-w-2xl">
                {isAr
                  ? 'تطبيقات مقصود ضعفها، تُشغَّل على شبكة الـ Sandbox الداخلية دون أي منفذ منشور على المضيف. كل حالة هنا مقروءة من Docker مباشرة، لا مفترضة.'
                  : 'Deliberately vulnerable applications, run on the internal sandbox network with no port published to the host. Every status here is read from Docker, not assumed.'}
              </p>
            </div>
          </div>

          <button
            onClick={() => load()}
            disabled={isLoading}
            className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition-colors flex items-center gap-2 shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : 'text-cyan-400'}`} />
            <span>{isAr ? 'تحديث الحالة' : 'Refresh status'}</span>
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-6 pt-5 border-t border-slate-800/80">
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">{isAr ? 'في الفهرس' : 'In catalog'}</span>
            <span className="text-xl font-bold font-mono text-slate-200">{labs.length}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">
              {isAr ? 'يجيب فعلاً' : 'Serving now'}
            </span>
            <span className="text-xl font-bold font-mono text-emerald-300">{running}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">
              {isAr ? 'قيد الإقلاع (الحاوية تعمل)' : 'Booting (container up)'}
            </span>
            <span className="text-xl font-bold font-mono text-amber-300">{starting}</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3">
            <span className="text-xs text-slate-400 block mb-1">
              {isAr ? 'منافذ منشورة للمضيف' : 'Ports published to host'}
            </span>
            <span className="text-xl font-bold font-mono text-emerald-300">0</span>
          </div>
        </div>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 text-xs text-slate-400 flex items-start gap-2.5">
        <Network className="w-4 h-4 shrink-0 mt-0.5 text-cyan-400" />
        <p className="leading-relaxed">
          {isAr
            ? 'العناوين المعروضة تُحلّ داخل شبكة الـ Sandbox فقط. لن تفتح من متصفحك، وهذا مقصود: تطبيق ضعيف متاح من المضيف حادثة أمنية لا مختبر.'
            : 'The addresses below resolve inside the sandbox network only. They will not open from your browser, by design: a vulnerable app reachable from the host is an incident, not a lab.'}
        </p>
      </div>

      {error && (
        <div className="bg-rose-950/30 border border-rose-500/30 rounded-xl p-4 text-sm text-rose-300 flex items-start gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {isLoading && labs.length === 0 && (
        <div className="text-center text-slate-500 py-12 text-sm">
          {isAr ? 'جاري قراءة حالة المختبرات...' : 'Reading lab status...'}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {labs.map((lab) => {
          const style = STATUS_STYLE[lab.status] ?? STATUS_STYLE.UNKNOWN;
          const pending = busy[lab.id];
          // The buttons act on the container, the chips describe the service:
          // `STARTING` means the container is up and must not be started again.
          const containerUp = lab.containerRunning === true;
          const readinessStyle =
            READINESS_STYLE[lab.readiness?.state ?? 'UNVERIFIED'] ?? READINESS_STYLE.UNVERIFIED;
          return (
            <div key={lab.id} className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${style.dot}`} />
                    <h4 className="text-sm font-bold text-slate-100 truncate">{lab.name}</h4>
                  </div>
                  <span className="text-[10px] font-mono text-cyan-400">@{lab.id}</span>
                </div>
                <span
                  className={`shrink-0 text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${style.chip}`}
                >
                  {style.icon}
                  <span>{isAr ? style.labelAr : style.labelEn}</span>
                </span>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">{lab.description}</p>

              {/* The backend's own account of why the lab is in this state. */}
              <p className="text-[11px] text-slate-500 leading-relaxed border-l-2 border-slate-800 pl-2">
                {lab.detail}
              </p>

              <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 pt-2 border-t border-slate-800 text-[11px] font-mono">
                <dt className="text-slate-500">{isAr ? 'المستوى' : 'Difficulty'}</dt>
                <dd>
                  <span
                    className={`px-1.5 py-0.5 rounded border ${
                      DIFFICULTY_STYLE[lab.difficulty] ?? 'text-slate-400 border-slate-700 bg-slate-950'
                    }`}
                  >
                    {lab.difficulty}
                  </span>
                </dd>

                <dt className="text-slate-500">{isAr ? 'عنوان داخلي' : 'Internal URL'}</dt>
                <dd className="text-slate-300 truncate" title={lab.internalUrl}>
                  {lab.internalUrl}
                </dd>

                <dt className="text-slate-500">{isAr ? 'الحاوية' : 'Container'}</dt>
                <dd className={lab.containerId ? 'text-slate-300' : 'text-slate-600'}>
                  {lab.containerId ?? (isAr ? 'لا توجد' : 'none')}
                </dd>

                {/* Container state and service readiness are two facts; the
                    status chip above only summarises them, so both are shown. */}
                <dt className="text-slate-500">{isAr ? 'حالة الحاوية' : 'Container state'}</dt>
                <dd className={containerUp ? 'text-emerald-300' : 'text-slate-400'}>
                  {lab.containerRunning === null
                    ? isAr
                      ? 'تعذّرت القراءة'
                      : 'unreadable'
                    : containerUp
                      ? isAr
                        ? 'تعمل'
                        : 'running'
                      : isAr
                        ? 'لا تعمل'
                        : 'not running'}
                </dd>

                <dt className="text-slate-500">{isAr ? 'الجاهزية' : 'Readiness'}</dt>
                <dd>
                  <span
                    className={`px-1.5 py-0.5 rounded border ${readinessStyle.className}`}
                    title={lab.readiness?.evidence}
                  >
                    {isAr ? readinessStyle.labelAr : readinessStyle.labelEn}
                  </span>
                </dd>
              </dl>

              {/* The probe's own account, shown verbatim when the two facts
                  disagree — a running container that is not answering. */}
              {containerUp && lab.readiness?.state !== 'READY' && (
                <p className="text-[11px] text-amber-300/90 leading-relaxed border-l-2 border-amber-800/60 pl-2">
                  {lab.readiness?.evidence}
                </p>
              )}

              <div className="text-[10px] font-mono text-slate-600 truncate" title={lab.image}>
                {lab.image}
              </div>

              <div className="flex gap-2 pt-1">
                <button
                  onClick={() => act(lab.id, 'start')}
                  disabled={!!pending || containerUp}
                  className="flex-1 px-3 py-2 text-xs font-medium bg-emerald-950/60 hover:bg-emerald-900/60 disabled:opacity-40 disabled:hover:bg-emerald-950/60 text-emerald-300 rounded-lg border border-emerald-800/60 transition-colors flex items-center justify-center gap-1.5"
                >
                  {pending === 'start' ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Play className="w-3.5 h-3.5" />
                  )}
                  <span>{isAr ? 'تشغيل' : 'Start'}</span>
                </button>
                <button
                  onClick={() => act(lab.id, 'stop')}
                  disabled={!!pending || !containerUp}
                  className="flex-1 px-3 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800 text-slate-200 rounded-lg border border-slate-700 transition-colors flex items-center justify-center gap-1.5"
                >
                  {pending === 'stop' ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Square className="w-3.5 h-3.5" />
                  )}
                  <span>{isAr ? 'إيقاف' : 'Stop'}</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
