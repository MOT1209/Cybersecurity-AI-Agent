/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared base for OpenAI-compatible `chat/completions` providers (Groq,
 * OpenCode Zen, ...). Uses the platform `fetch` — no vendor SDK, no new
 * dependency, no new supply-chain surface for a security platform.
 *
 * Environment is read lazily on every call (never snapshotted at import),
 * so tests can set/unset keys and `isAvailable()` stays truthful.
 */

import type {
  LLMProvider,
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  GenerateJSONResult,
} from "./types";
import { INJECTION_GUARD } from "./types";

export interface OpenAICompatibleOptions {
  id: string;
  baseUrl: () => string;
  /** Defaults to `/chat/completions`. Overridable for gateways like Zen whose
   *  path may differ per model — see `zenProvider.ts`. */
  chatPath?: () => string;
  apiKey: () => string | undefined;
  model: () => string;
  missingKeyHint: string;
  /** Send `response_format: { type: "json_object" }`. Only for providers that
   *  document JSON mode (Groq does); heterogeneous gateways parse instead. */
  jsonMode?: boolean;
  timeoutMs?: number;
}

function clampTemperature(t: number | undefined, fallback: number): number {
  if (t === undefined || Number.isNaN(t)) return fallback;
  return Math.min(2, Math.max(0, t));
}

/** Minimal shape of an OpenAI-compatible chat-completions response. */
interface OpenAIChatResponse {
  choices?: Array<{ message?: { content?: unknown } }>;
}

export class OpenAICompatibleProvider implements LLMProvider {
  readonly id: string;
  private readonly opts: OpenAICompatibleOptions;

  constructor(opts: OpenAICompatibleOptions) {
    this.id = opts.id;
    this.opts = opts;
  }

  isAvailable(): boolean {
    return Boolean(this.opts.apiKey());
  }

  private async post(body: unknown): Promise<OpenAIChatResponse> {
    const key = this.opts.apiKey();
    if (!key) {
      throw new Error(`${this.id} provider unavailable: ${this.opts.missingKeyHint}`);
    }
    const base = this.opts.baseUrl().replace(/\/$/, "");
    const path = this.opts.chatPath ? this.opts.chatPath() : "/chat/completions";
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.opts.timeoutMs ?? 25000);
    try {
      const res = await fetch(`${base}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${key}`,
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      if (!res.ok) {
        throw new Error(`${this.id} HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
      }
      return (await res.json()) as OpenAIChatResponse;
    } finally {
      clearTimeout(timer);
    }
  }

  private static choiceText(data: OpenAIChatResponse, id: string): string {
    const text = data?.choices?.[0]?.message?.content;
    if (typeof text !== "string" || !text) {
      throw new Error(`${id} returned no text content`);
    }
    return text;
  }

  async generate(messages: ChatMessage[], options?: GenerateOptions): Promise<GenerateResult> {
    const system = `${options?.system ?? ""}\n${INJECTION_GUARD}`.trim();
    const data = await this.post({
      model: this.opts.model(),
      messages: [
        ...(system ? [{ role: "system", content: system }] : []),
        ...messages.map((m) => ({ role: m.role, content: m.content })),
      ],
      temperature: clampTemperature(options?.temperature, 0.4),
      ...(options?.maxTokens ? { max_tokens: options.maxTokens } : {}),
    });
    return {
      text: OpenAICompatibleProvider.choiceText(data, this.id),
      provider: this.id,
      fallback: false,
    };
  }

  async generateJSON<T = unknown>(
    prompt: string,
    schemaHint: string,
    options?: GenerateOptions,
  ): Promise<GenerateJSONResult<T>> {
    const data = await this.post({
      model: this.opts.model(),
      messages: [
        {
          role: "system",
          content:
            `${options?.system ?? ""}\nReturn ONLY valid JSON, no prose or code fences. ${schemaHint}\n${INJECTION_GUARD}`.trim(),
        },
        { role: "user", content: prompt },
      ],
      temperature: clampTemperature(options?.temperature, 0.3),
      ...(options?.maxTokens ? { max_tokens: options.maxTokens } : {}),
      ...(this.opts.jsonMode ? { response_format: { type: "json_object" } } : {}),
    });
    const raw = OpenAICompatibleProvider.choiceText(data, this.id).trim();
    // Strip accidental code fences before parsing (same convention as Claude).
    const cleaned = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
    const parsed = JSON.parse(cleaned || "{}") as T;
    return { data: parsed, provider: this.id, fallback: false };
  }
}
