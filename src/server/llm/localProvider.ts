/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Deterministic local provider. Always available, never calls the network.
 * Serves as the guaranteed fallback so the platform stays fully functional
 * with no API keys configured. It does not fabricate AI reasoning — it returns
 * clearly-labelled deterministic scaffolding the caller can present as such.
 */

import type {
  LLMProvider,
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  GenerateJSONResult,
} from "./types";

export class LocalProvider implements LLMProvider {
  readonly id = "local";

  isAvailable(): boolean {
    return true;
  }

  async generate(messages: ChatMessage[], _options?: GenerateOptions): Promise<GenerateResult> {
    const last = [...messages].reverse().find((m) => m.role === "user");
    const echo = last?.content?.slice(0, 280) ?? "";
    return {
      text:
        "⚙️ [Local engine — no live model configured]\n" +
        "تم استلام طلبك محلياً. لتفعيل الردود الذكية الحقيقية اضبط مزوّداً (GEMINI_API_KEY أو ANTHROPIC_API_KEY).\n" +
        (echo ? `\nملخص المدخل: ${echo}` : ""),
      provider: this.id,
      fallback: true,
    };
  }

  async generateJSON<T = unknown>(
    _prompt: string,
    _schemaHint: string,
    _options?: GenerateOptions,
  ): Promise<GenerateJSONResult<T>> {
    // Callers that need domain-specific fallbacks (e.g. the orchestrator plan)
    // provide their own; this returns an empty object as a safe default.
    return { data: {} as T, provider: this.id, fallback: true };
  }
}
