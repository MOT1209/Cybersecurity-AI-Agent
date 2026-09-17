/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Groq provider — OpenAI-compatible `chat/completions` behind the
 * LLMProvider interface. `fetch`-only: no `groq-sdk`, no new dependency.
 *
 * Configuration:
 *   GROQ_API_KEY   Bearer key from the Groq console (required).
 *   GROQ_MODEL     Model id, default `llama-3.3-70b-versatile`.
 *   GROQ_BASE_URL  Override, default `https://api.groq.com/openai/v1`.
 */

import { OpenAICompatibleProvider } from "./openaiCompatible";

export class GroqProvider extends OpenAICompatibleProvider {
  constructor() {
    super({
      id: "groq",
      baseUrl: () => process.env.GROQ_BASE_URL || "https://api.groq.com/openai/v1",
      apiKey: () => process.env.GROQ_API_KEY,
      model: () => process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
      missingKeyHint: "GROQ_API_KEY not set",
      jsonMode: true,
    });
  }
}
