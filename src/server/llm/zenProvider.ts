/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * OpenCode Zen provider — the Zen AI gateway behind the LLMProvider
 * interface. `fetch`-only: no new dependency.
 *
 * Configuration:
 *   OPENCODE_API_KEY (or OPENCODE_ZEN_API_KEY)  Key from the Zen dashboard.
 *   ZEN_MODEL        Model id, default `gemini-3-flash`.
 *   ZEN_BASE_URL     Override, default `https://opencode.ai/zen/v1`.
 *   ZEN_CHAT_PATH    Override, default `/chat/completions`.
 *
 * Honesty note: Zen routes models heterogeneously (`/responses` for some,
 * model-specific paths for others). This provider speaks the OpenAI
 * `chat/completions` shape, which the Zen gateway documents for its
 * OpenAI-SDK-compatible models. Before relying on a specific model, verify
 * with `GET <ZEN_BASE_URL>/models` using your key; a model on a different
 * route fails loudly (never silently) and the platform falls through to the
 * next available provider. `jsonMode` is deliberately off: heterogeneous
 * gateways are prompted + parsed instead of assumed.
 */

import { OpenAICompatibleProvider } from "./openaiCompatible";

export class ZenProvider extends OpenAICompatibleProvider {
  constructor() {
    super({
      id: "zen",
      baseUrl: () => process.env.ZEN_BASE_URL || "https://opencode.ai/zen/v1",
      chatPath: () => process.env.ZEN_CHAT_PATH || "/chat/completions",
      apiKey: () => process.env.OPENCODE_API_KEY || process.env.OPENCODE_ZEN_API_KEY,
      model: () => process.env.ZEN_MODEL || "gemini-3-flash",
      missingKeyHint: "OPENCODE_API_KEY (or OPENCODE_ZEN_API_KEY) not set",
      jsonMode: false,
    });
  }
}
