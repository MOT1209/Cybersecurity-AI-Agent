/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Approvals centre (§15).
 *
 * Shows every request a high-risk tool raised and lets a human decide it. Two
 * properties this page must not obscure:
 *   - the decider is the AUTHENTICATED principal, not a name typed into a form,
 *     so the "approver must differ from requester" rule cannot be side-stepped;
 *   - the granted token is shown EXACTLY ONCE, because redeeming it burns it.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../lib/api';
import {
  KeyRound,
  RefreshCw,
  Check,
  X,
  Clock,
  ShieldAlert,
  Copy,
  CheckCheck,
} from 'lucide-react';
import { useCopy } from '../lib/useCopy';

interface ApprovalsCenterProps {
  language: 'ar' | 'en';
}

type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'CONSUMED' | 'EXPIRED';

interface ApprovalRequest {
  id: string;
  status: ApprovalStatus;
  task: string;
  target: string;
  toolId: string;
  reason: string;
  scope: string;
  riskLevel: string;
  expectedImpact: string;
  projectId: string;
  requestedBy: string;
  decidedBy?: string;
  decidedAt?: string;
  createdAt: string;
  expiresAt: string;
}

const STATUS_STYLE: Record<ApprovalStatus, string> = {
  PENDING: 'bg-amber-950/80 text-amber-300 border-amber-700/60',
  APPROVED: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60',
  REJECTED: 'bg-rose-950/80 text-rose-300 border-rose-700/60',
  CONSUMED: 'bg-slate-900 text-slate-400 border-slate-700',
  EXPIRED: 'bg-slate-900 text-slate-500 border-slate-800',
};

export const ApprovalsCenter: React.FC<ApprovalsCenterProps> = ({ language }) => {
  const isAr = language === 'ar';
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [deciding, setDeciding] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Tokens are shown once, never re-fetchable. Kept only in this component. */
  const [issuedTokens, setIssuedTokens] = useState<Record<string, string>>({});
  const { copy, isCopied } = useCopy();

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await apiFetch('/api/approvals');
      if (res.ok) {
        const data = await res.json();
        setApprovals(data.approvals ?? []);
      }
    } catch (e) {
      console.warn('Failed to load approvals', e);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const decide = async (id: string, decision: 'APPROVED' | 'REJECTED') => {
    setDeciding(id);
    setError(null);
    try {
      // No decidedBy is sent: the server uses the authenticated principal, and
      // sending one here would be ignored anyway.
      const res = await apiFetch(`/api/approvals/${id}/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.message || `HTTP ${res.status}`);
        return;
      }
      if (data.approvalToken) {
        setIssuedTokens((prev) => ({ ...prev, [id]: data.approvalToken }));
      }
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDeciding(null);
    }
  };

  const pending = approvals.filter((a) => a.status === 'PENDING');

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      <div className="bg-slate-900/90 border border-amber-500/20 rounded-2xl p-6 backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-amber-950/80 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <KeyRound className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100">
                {isAr ? 'مركز الموافقات البشرية' : 'Human Approvals'}
              </h2>
              <p className="text-sm text-slate-400 mt-1 max-w-2xl">
                {isAr
                  ? 'الأدوات عالية الخطورة لا تعمل بلا قرار بشري. المُقرِّر هو الهوية المُصادَق عليها، ولا يمكن لمن طلب التنفيذ أن يوافق على طلبه.'
                  : 'High-risk tools do not run without a human decision. The decider is the authenticated identity, and a requester can never approve its own request.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
              <span className="text-[11px] text-slate-400 block">{isAr ? 'بانتظار قرار' : 'Pending'}</span>
              <span className="text-lg font-bold font-mono text-amber-300">{pending.length}</span>
            </div>
            <button
              onClick={load}
              disabled={isLoading}
              className="px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition-colors flex items-center gap-2"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : 'text-cyan-400'}`} />
              <span>{isAr ? 'تحديث' : 'Refresh'}</span>
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-rose-950/30 border border-rose-500/30 rounded-xl p-4 text-sm text-rose-300 flex items-start gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold mb-0.5">{isAr ? 'رُفض القرار' : 'Decision refused'}</div>
            <div className="text-rose-200/80 text-xs">{error}</div>
          </div>
        </div>
      )}

      {!isLoading && approvals.length === 0 && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 text-sm">
          {isAr
            ? 'لا توجد طلبات موافقة. تُفتح تلقائياً عند محاولة تشغيل أداة عالية الخطورة.'
            : 'No approval requests. One opens automatically when a high-risk tool is attempted.'}
        </div>
      )}

      <div className="space-y-3">
        {approvals.map((a) => (
          <div key={a.id} className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
              <div className="min-w-0 space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${STATUS_STYLE[a.status]}`}>
                    {a.status}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-orange-800/60 bg-orange-950/50 text-orange-300">
                    {a.riskLevel}
                  </span>
                  <span className="text-[10px] font-mono text-cyan-400">@{a.toolId}</span>
                </div>
                <h4 className="text-sm font-semibold text-slate-100">{a.task}</h4>
                <p className="text-xs text-slate-400">{a.expectedImpact}</p>
              </div>

              {a.status === 'PENDING' && (
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => decide(a.id, 'APPROVED')}
                    disabled={deciding === a.id}
                    className="px-3 py-1.5 text-xs font-medium rounded-md bg-emerald-950/80 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-700/60 flex items-center gap-1.5 transition-colors"
                  >
                    <Check className="w-3.5 h-3.5" />
                    <span>{isAr ? 'موافقة' : 'Approve'}</span>
                  </button>
                  <button
                    onClick={() => decide(a.id, 'REJECTED')}
                    disabled={deciding === a.id}
                    className="px-3 py-1.5 text-xs font-medium rounded-md bg-rose-950/80 hover:bg-rose-900/80 text-rose-300 border border-rose-700/60 flex items-center gap-1.5 transition-colors"
                  >
                    <X className="w-3.5 h-3.5" />
                    <span>{isAr ? 'رفض' : 'Reject'}</span>
                  </button>
                </div>
              )}
            </div>

            <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-3 gap-y-1.5 pt-2 border-t border-slate-800 text-[11px] font-mono">
              <dt className="text-slate-500">{isAr ? 'الهدف' : 'Target'}</dt>
              <dd className="text-slate-300 truncate md:col-span-3">{a.target}</dd>

              <dt className="text-slate-500">{isAr ? 'مقدّم الطلب' : 'Requested by'}</dt>
              <dd className="text-slate-300 truncate">{a.requestedBy}</dd>

              <dt className="text-slate-500">{isAr ? 'قرّرها' : 'Decided by'}</dt>
              <dd className={a.decidedBy ? 'text-slate-300 truncate' : 'text-slate-600'}>
                {a.decidedBy ?? '—'}
              </dd>

              <dt className="text-slate-500">{isAr ? 'النطاق' : 'Scope'}</dt>
              <dd className="text-slate-300 truncate">{a.scope}</dd>

              <dt className="text-slate-500 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {isAr ? 'ينتهي' : 'Expires'}
              </dt>
              <dd className="text-slate-400 truncate">{new Date(a.expiresAt).toLocaleString()}</dd>
            </dl>

            <p className="text-xs text-slate-500">{a.reason}</p>

            {issuedTokens[a.id] && (
              <div className="bg-emerald-950/20 border border-emerald-700/40 rounded-lg p-3 space-y-2">
                <div className="text-[11px] font-mono text-emerald-300">
                  {isAr
                    ? 'رمز الموافقة — يُعرض مرة واحدة فقط، ويُستهلك عند أول استخدام'
                    : 'Approval token — shown once, burned on first use'}
                </div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 min-w-0 text-[10px] font-mono text-emerald-200 bg-slate-950 border border-slate-800 rounded px-2 py-1.5 truncate">
                    {issuedTokens[a.id]}
                  </code>
                  <button
                    onClick={() => copy(issuedTokens[a.id], a.id)}
                    className="px-2 py-1.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 shrink-0"
                  >
                    {isCopied(a.id) ? (
                      <CheckCheck className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
                <div className="text-[10px] text-slate-500">
                  {isAr
                    ? 'مربوط بهذه الأداة وهذا الهدف تحديداً؛ لا يصلح لغيرهما.'
                    : 'Bound to this exact tool and target; it cannot be reused elsewhere.'}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
