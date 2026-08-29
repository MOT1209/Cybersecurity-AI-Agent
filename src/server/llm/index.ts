/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * LLM registry + resolver. Selects a provider chain and always guarantees a
 * result via the local fallback.
 *
 * Selection order:
 *   1. explicit AI_PROVIDER env ("claude" | "gemini" | "local")
 *   2. first available provider in preference order (claude → gemini)
 *   3. local deterministic fallback
 */

import type {
  LLMProvider,
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  GenerateJSONResult,
} from "./types";
import { ClaudeProvider } from "./claudeProvider";
import { GeminiProvider } from "./geminiProvider";
import { LocalProvider } from "./localProvider";

export * from "./types";

const claude = new ClaudeProvider();
const gemini = new GeminiProvider();
const local = new LocalProvider();

const byId: Record<string, LLMProvider> = {
  claude,
  gemini,
  local,
};

/** Preference order when AI_PROVIDER is not pinned. */
const PREFERENCE: LLMProvider[] = [claude, gemini];

/** Resolve the primary provider honoring AI_PROVIDER, else first available. */
export function resolveProvider(): LLMProvider {
  const pinned = process.env.AI_PROVIDER?.trim().toLowerCase();
  if (pinned && byId[pinned]) {
    const p = byId[pinned];
    if (p.isAvailable()) return p;
    // Pinned but unusable → fall through to auto-select rather than crash.
  }
  return PREFERENCE.find((p) => p.isAvailable()) ?? local;
}

/**
 * Text generation that never throws for lack of a model: on any provider error
 * it degrades to the local deterministic provider.
 */
export async function generate(
  messages: ChatMessage[],
  options?: GenerateOptions,
): Promise<GenerateResult> {
  const provider = resolveProvider();
  try {
    return await provider.generate(messages, options);
  } catch {
    return local.generate(messages, options);
  }
}

/**
 * JSON generation with graceful degradation. If the resolved provider fails,
 * the caller-supplied `localFallback` (domain-specific) is used; if none is
 * given, an empty object is returned and `fallback` is true.
 */
export async function generateJSON<T = unknown>(
  prompt: string,
  schemaHint: string,
  options?: GenerateOptions,
  localFallback?: () => T,
): Promise<GenerateJSONResult<T>> {
  const provider = resolveProvider();
  // No live model: the local provider can't produce domain JSON, so use the
  // caller's domain-specific fallback directly rather than an empty object.
  if (provider.id === "local") {
    if (localFallback) {
      return { data: localFallback(), provider: "local", fallback: true };
    }
    return { data: {} as T, provider: "local", fallback: true };
  }
  try {
    return await provider.generateJSON<T>(prompt, schemaHint, options);
  } catch {
    if (localFallback) {
      return { data: localFallback(), provider: "local", fallback: true };
    }
    return { data: {} as T, provider: "local", fallback: true };
  }
}

/** Diagnostic snapshot (no secrets) — safe for authenticated status views. */
export function providerStatus() {
  return {
    active: resolveProvider().id,
    available: Object.values(byId)
      .filter((p) => p.isAvailable())
      .map((p) => p.id),
  };
}
