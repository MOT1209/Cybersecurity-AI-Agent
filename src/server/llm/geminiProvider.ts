/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Gemini provider — wraps @google/genai behind the LLMProvider interface.
 * Preserves the model-config and injection-guard conventions from server.ts.
 */

import { GoogleGenAI } from "@google/genai";
import type {
  LLMProvider,
  ChatMessage,
  GenerateOptions,
  GenerateResult,
  GenerateJSONResult,
} from "./types";
import { INJECTION_GUARD } from "./types";

const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

export class GeminiProvider implements LLMProvider {
  readonly id = "gemini";
  private client: GoogleGenAI | null = null;

  private getClient(): GoogleGenAI | null {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return null;
    if (!this.client) {
      this.client = new GoogleGenAI({
        apiKey,
        httpOptions: { headers: { "User-Agent": "aistudio-build" } },
      });
    }
    return this.client;
  }

  isAvailable(): boolean {
    return Boolean(process.env.GEMINI_API_KEY);
  }

  async generate(messages: ChatMessage[], options?: GenerateOptions): Promise<GenerateResult> {
    const ai = this.getClient();
    if (!ai) throw new Error("Gemini provider unavailable: GEMINI_API_KEY not set");

    const contents = messages.map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }],
    }));

    const response = await ai.models.generateContent({
      model: GEMINI_MODEL,
      contents,
      config: {
        systemInstruction: `${options?.system ?? ""}\n${INJECTION_GUARD}`.trim(),
        temperature: options?.temperature ?? 0.4,
        ...(options?.maxTokens ? { maxOutputTokens: options.maxTokens } : {}),
      },
    });

    return { text: response.text || "", provider: this.id, fallback: false };
  }

  async generateJSON<T = unknown>(
    prompt: string,
    schemaHint: string,
    options?: GenerateOptions,
  ): Promise<GenerateJSONResult<T>> {
    const ai = this.getClient();
    if (!ai) throw new Error("Gemini provider unavailable: GEMINI_API_KEY not set");

    const response = await ai.models.generateContent({
      model: GEMINI_MODEL,
      contents: prompt,
      config: {
        systemInstruction:
          `${options?.system ?? ""}\nReturn ONLY valid JSON. ${schemaHint}\n${INJECTION_GUARD}`.trim(),
        responseMimeType: "application/json",
        temperature: options?.temperature ?? 0.3,
      },
    });

    const data = JSON.parse(response.text || "{}") as T;
    return { data, provider: this.id, fallback: false };
  }
}
