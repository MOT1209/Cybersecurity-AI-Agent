/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Claude provider — wraps @anthropic-ai/sdk behind the LLMProvider interface.
 * The SDK is imported lazily so the platform still builds and runs when the
 * package isn't installed; the provider simply reports itself unavailable.
 */

import type {
  LLMProvider,
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  GenerateJSONResult,
} from "./types";
import { INJECTION_GUARD } from "./types";

const CLAUDE_MODEL = process.env.CLAUDE_MODEL || "claude-sonnet-5";

export class ClaudeProvider implements LLMProvider {
  readonly id = "claude";
  private client: any = null;
  private sdkMissing = false;

  private async getClient(): Promise<any | null> {
    if (!process.env.ANTHROPIC_API_KEY || this.sdkMissing) return null;
    if (this.client) return this.client;
    try {
      // Lazy dynamic import: no hard dependency at build time.
      const mod: any = await import("@anthropic-ai/sdk");
      const Anthropic = mod.default ?? mod.Anthropic;
      this.client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
      return this.client;
    } catch {
      this.sdkMissing = true;
      return null;
    }
  }

  isAvailable(): boolean {
    return Boolean(process.env.ANTHROPIC_API_KEY) && !this.sdkMissing;
  }

  async generate(messages: ChatMessage[], options?: GenerateOptions): Promise<GenerateResult> {
    const client = await this.getClient();
    if (!client) throw new Error("Claude provider unavailable: ANTHROPIC_API_KEY or SDK missing");

    const response = await client.messages.create({
      model: CLAUDE_MODEL,
      max_tokens: options?.maxTokens ?? 2048,
      temperature: options?.temperature ?? 0.4,
      system: `${options?.system ?? ""}\n${INJECTION_GUARD}`.trim(),
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
    });

    const text = (response.content ?? [])
      .filter((b: any) => b.type === "text")
      .map((b: any) => b.text)
      .join("");
    return { text, provider: this.id, fallback: false };
  }

  async generateJSON<T = unknown>(
    prompt: string,
    schemaHint: string,
    options?: GenerateOptions,
  ): Promise<GenerateJSONResult<T>> {
    const client = await this.getClient();
    if (!client) throw new Error("Claude provider unavailable: ANTHROPIC_API_KEY or SDK missing");

    const response = await client.messages.create({
      model: CLAUDE_MODEL,
      max_tokens: options?.maxTokens ?? 4096,
      temperature: options?.temperature ?? 0.3,
      system:
        `${options?.system ?? ""}\nReturn ONLY valid JSON, no prose or code fences. ${schemaHint}\n${INJECTION_GUARD}`.trim(),
      messages: [{ role: "user", content: prompt }],
    });

    const raw = (response.content ?? [])
      .filter((b: any) => b.type === "text")
      .map((b: any) => b.text)
      .join("")
      .trim();
    // Strip accidental code fences before parsing.
    const cleaned = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
    const data = JSON.parse(cleaned || "{}") as T;
    return { data, provider: this.id, fallback: false };
  }
}
