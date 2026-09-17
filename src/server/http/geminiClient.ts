/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Gemini client factory for the HTTP layer. Kept module-scoped so every route
 * group shares one client and the same model pick. NOTE: must be a real,
 * currently-served model — an invalid id makes every live AI call fail and
 * silently fall back to the local deterministic engine.
 */

import { GoogleGenAI } from "@google/genai";

export const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";

let aiClient: GoogleGenAI | null = null;
export function getAIClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}