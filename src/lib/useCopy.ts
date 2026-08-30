/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * One copy-to-clipboard hook, replacing six near-identical copies of the
 * same "copy, flip a flag, reset it after 2s" block. Those copies each set a
 * timeout without clearing it on unmount, which warns when a tab is switched
 * mid-timer; this clears on unmount and on re-copy.
 *
 * navigator.clipboard rejects on denied permission and is undefined on
 * insecure origins, so the write is guarded rather than assumed.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

export interface UseCopyResult {
  /** Key of the most recently copied item, or null. */
  copied: string | null;
  /** True when `key` is the most recently copied item. */
  isCopied: (key: string) => boolean;
  /** Returns true on success, false if the clipboard was unavailable. */
  copy: (text: string, key?: string) => Promise<boolean>;
  error: string | null;
}

export function useCopy(resetMs = 2000): UseCopyResult {
  const [copied, setCopied] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clear = useCallback(() => {
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  useEffect(() => clear, [clear]);

  const copy = useCallback(
    async (text: string, key = 'default'): Promise<boolean> => {
      clear();
      try {
        if (!navigator.clipboard?.writeText) {
          throw new Error('Clipboard API unavailable');
        }
        await navigator.clipboard.writeText(text);
        setError(null);
        setCopied(key);
        timer.current = setTimeout(() => setCopied(null), resetMs);
        return true;
      } catch (e) {
        setCopied(null);
        setError(e instanceof Error ? e.message : 'Copy failed');
        return false;
      }
    },
    [clear, resetMs],
  );

  const isCopied = useCallback((key: string) => copied === key, [copied]);

  return { copied, isCopied, copy, error };
}
