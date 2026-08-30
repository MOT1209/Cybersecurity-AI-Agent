/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Isolates a crashing tab so one bad render does not blank the whole app.
 * This matters here because several panels render shapes that come straight
 * from an LLM response, and those are not guaranteed to match our types.
 */

import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface ErrorBoundaryProps {
  children: React.ReactNode;
  language: 'ar' | 'en';
  /** Remounts the subtree when this changes — pass the active tab id. */
  resetKey?: string;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidUpdate(prev: ErrorBoundaryProps) {
    // Switching tabs clears a previous tab's error instead of stranding it.
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack);
  }

  private reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    const isAr = this.props.language === 'ar';

    return (
      <div className="max-w-3xl mx-auto my-10 px-4">
        <div className="rounded-xl border border-rose-900/60 bg-rose-950/20 p-6">
          <div className="flex items-center gap-3 mb-3">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
            <h2 className="text-base font-bold text-rose-200">
              {isAr ? 'تعطّل هذا القسم' : 'This section crashed'}
            </h2>
          </div>

          <p className="text-sm text-slate-400 mb-4 leading-relaxed">
            {isAr
              ? 'حدث خطأ غير متوقع أثناء عرض هذا القسم. بقية المنصة تعمل بشكل طبيعي — يمكنك إعادة المحاولة أو الانتقال إلى قسم آخر.'
              : 'Something went wrong rendering this section. The rest of the platform is unaffected — retry, or switch to another section.'}
          </p>

          <pre
            dir="ltr"
            className="text-[11px] font-mono text-rose-300/80 bg-slate-950/70 border border-slate-800 rounded-lg p-3 mb-4 overflow-x-auto whitespace-pre-wrap break-words"
          >
            {error.message || String(error)}
          </pre>

          <button
            type="button"
            onClick={this.reset}
            className="inline-flex items-center gap-2 text-sm font-semibold rounded-lg px-4 py-2 bg-rose-500/15 text-rose-200 border border-rose-800 hover:bg-rose-500/25 transition"
          >
            <RotateCcw className="w-4 h-4" />
            {isAr ? 'إعادة المحاولة' : 'Retry'}
          </button>
        </div>
      </div>
    );
  }
}
