/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * LLM registry + resolver. Selects a provider chain and always guarantees a
 * result via the local fallback.
 *
 * Selection order:
 *   1. explicit AI_PROVIDER env ("zen" | "groq" | "claude" | "gemini" | "local")
 *   2. first available provider in preference order (zen → groq → claude → gemini)
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
import { GroqProvider } from "./groqProvider";
import { ZenProvider } from "./zenProvider";
import { LocalProvider } from "./localProvider";

export * from "./types";

const claude = new ClaudeProvider();
const gemini = new GeminiProvider();
const groq = new GroqProvider();
const zen = new ZenProvider();
const local = new LocalProvider();

const byId: Record<string, LLMProvider> = {
  zen,
  groq,
  claude,
  gemini,
  local,
};

/** Preference order when AI_PROVIDER is not pinned (cheapest/fastest first). */
const PREFERENCE: LLMProvider[] = [zen, groq, claude, gemini];

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
 * Ordered candidate providers: the pinned one first (when usable), then the
 * rest in preference order. A pinned-but-unusable id falls through to
 * auto-select rather than crashing.
 */
function orderedProviders(): LLMProvider[] {
  const pinned = process.env.AI_PROVIDER?.trim().toLowerCase();
  const available = PREFERENCE.filter((p) => p.isAvailable());
  if (pinned && byId[pinned]) {
    const p = byId[pinned];
    if (p.isAvailable() && p.id !== "local") {
      return [p, ...available.filter((x) => x !== p)];
    }
  }
  return available;
}

/**
 * Text generation that never throws for lack of a model: every available
 * provider is tried in order, and only when all fail (or none is configured)
 * does it degrade to the local deterministic provider.
 */
export async function generate(
  messages: ChatMessage[],
  options?: GenerateOptions,
): Promise<GenerateResult> {
  for (const provider of orderedProviders()) {
    try {
      return await provider.generate(messages, options);
    } catch {
      // Try the next available provider — never fail on one vendor's outage.
    }
  }
  return local.generate(messages, options);
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
  for (const provider of orderedProviders()) {
    try {
      return await provider.generateJSON<T>(prompt, schemaHint, options);
    } catch {
      // Try the next available provider before any domain fallback.
    }
  }
  // No live model: the local provider can't produce domain JSON, so use the
  // caller's domain-specific fallback directly rather than an empty object.
  if (localFallback) {
    return { data: localFallback(), provider: "local", fallback: true };
  }
  return { data: {} as T, provider: "local", fallback: true };
}

/** Diagnostic snapshot (no secrets) — safe for authenticated status views. */
export function providerStatus() {
  const order = [...PREFERENCE, local];
  return {
    active: resolveProvider().id,
    available: order.filter((p) => p.isAvailable()).map((p) => p.id),
  };
}
