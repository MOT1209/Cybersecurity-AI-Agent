/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared API client for the CyberAgent AI frontend.
 *
 * All backend calls MUST go through `apiFetch` so that the optional
 * `x-api-key` header (matching the server's `APP_ACCESS_KEY`) is attached
 * consistently. Without this the SPA breaks entirely whenever the backend
 * has authentication enabled.
 *
 * Configure the key at build/deploy time via the Vite env var
 * `VITE_APP_ACCESS_KEY`. When it is empty the header is simply omitted,
 * which matches the server's "open access" development mode.
 */

const ACCESS_KEY: string =
  (import.meta.env.VITE_APP_ACCESS_KEY as string | undefined)?.trim() || '';

export function apiFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers || {});
  if (ACCESS_KEY && !headers.has('x-api-key')) {
    headers.set('x-api-key', ACCESS_KEY);
  }
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  return fetch(input, { ...init, headers });
}
