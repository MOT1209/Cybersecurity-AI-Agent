/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Global test setup.
 *
 * The suite was reaching the LIVE Gemini API: `.env` is loaded by the server at
 * import time, and two routes call `getAIClient()` directly rather than going
 * through the provider layer, so setting AI_PROVIDER=local in a test file did
 * not stop them. That made runs depend on a paid quota — and they intermittently
 * failed with HTTP 429 and then timed out.
 *
 * Clearing the credentials here means no test can reach an external model, by
 * construction rather than by discipline. Anything needing model behavior must
 * stub it explicitly.
 *
 * They are set to EMPTY rather than deleted: server.ts calls dotenv.config() at
 * import time, and dotenv fills in any key missing from process.env. An empty
 * value keeps the property present, so dotenv leaves it alone — and every
 * provider treats an empty key as "not configured".
 */

process.env.GEMINI_API_KEY = "";
process.env.ANTHROPIC_API_KEY = "";
process.env.AI_PROVIDER = "local";
// Groq / Zen keys must not leak in from a dev .env either: provider
// resolution tests assert exact auto-selection.
process.env.GROQ_API_KEY = "";
process.env.OPENCODE_API_KEY = "";
process.env.OPENCODE_ZEN_API_KEY = "";

// Auth must not leak in from a dev .env either: most suites assert the
// open-dev contract (anonymous viewer), while the RBAC/approvals suites opt
// into principals explicitly per file. Set to EMPTY (not deleted): dotenv
// fills any missing key from .env at import time, and empty reads as
// "not configured" to both the middleware and parsePrincipals.
process.env.APP_ACCESS_KEY = "";
process.env.API_PRINCIPALS = "";

// Tools must never reach a real network or Docker daemon from a test.
process.env.SANDBOX_MODE ??= "simulate";

// Persistence defaults to memory; a stray DATABASE_URL would make the suite
// fail closed at startup, which is correct behavior but not a unit-test concern.
process.env.DATABASE_URL = "";
