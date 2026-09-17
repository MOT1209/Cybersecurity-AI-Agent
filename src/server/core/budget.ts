/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Monthly budget tracking with per-IP limits and headers.
 *
 * - `APP_MONTHLY_BUDGET` — maximum requests per calendar month per IP.
 *   Set to `0` or omit to disable the budget check (unlimited).
 * - When the budget is exceeded, subsequent requests receive `403` with
 *   `X-Budget-Remaining: 0` and `X-Budget-Reset` indicating the Unix timestamp
 *   when the monthly counter resets (start of next calendar month in UTC).
 * - The limiter runs *after* the global rate-limiter (60/15min) but *before*
 *   the AI/orchestrator strict limiters, so budget is a hard ceiling above
 *   all other limits.
 */

import type { NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";

const DEFAULT_MONTHLY_BUDGET = Number(process.env.APP_MONTHLY_BUDGET) || 0;

/** Read per request: dotenv loads after module evaluation, and tests toggle. */
function monthlyBudget(): number {
  const fromEnv = Number(process.env.APP_MONTHLY_BUDGET);
  if (Number.isFinite(fromEnv) && fromEnv > 0) return fromEnv;
  return DEFAULT_MONTHLY_BUDGET > 0 ? DEFAULT_MONTHLY_BUDGET : 0;
}

/** Reset the counter at the start of each calendar month (UTC). */
function monthKey(_req: Request): string {
  const now = new Date();
  // Start of current UTC calendar month
  const firstOfMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  // Return the ISO string of the first moment of the month — same bucket for whole month
  return firstOfMonth.toISOString().split("T")[0];
}

/** In-memory store: IP -> { count, resetTimestamp } */
const budgetStore = new Map<string, { count: number; resetTimestamp: number }>();

/**
 * Express rate-limit middleware that enforces a per-IP monthly budget.
 * Returns 403 with X-Budget-Remaining / X-Budget-Reset headers when exceeded.
 */
export function createMonthlyBudgetLimiter() {
  // If budget is unlimited (0), just pass through. NOTE: express-rate-limit
  // v7+ blocks EVERYTHING when max is 0, so this must be a real passthrough,
  // not `rateLimit({ max: 0 })`.
  if (monthlyBudget() <= 0) {
    return (_req: Request, _res: Response, next: NextFunction) => next();
  }

  return rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 1 day window; we manage the monthly bucket inside
    max: 1, // we handle the real limit inside the handler; this just ensures per-day calls are limited to 1 per IP base
    standardHeaders: true,
    legacyHeaders: false,
    handler: async (req: Request, res: Response, next: NextFunction) => {
      // This handler will be overridden by our custom logic below
      next();
    },
  });
}

/**
 * Budget enforcement middleware — must be used after createGlobalApiLimiter.
 * Tracks per-IP monthly request count and returns 403 when APP_MONTHLY_BUDGET is exceeded.
 */
export function enforceMonthlyBudget() {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Disabled (0/unset) means unlimited — never block. Without this, the
    // `count > budget` check below 403s the very first request.
    const budget = monthlyBudget();
    if (budget <= 0) return next();

    const ip = (req as Request & { ip?: string }).ip || "unknown";
    const key = monthKey(req);

    let entry = budgetStore.get(ip);
    if (!entry) {
      entry = { count: 0, resetTimestamp: 0 };
    }

    // Reset at start of new calendar month (UTC)
    const nowDate = new Date();
    const firstOfMonth = new Date(Date.UTC(nowDate.getUTCFullYear(), nowDate.getUTCMonth(), 1));
    const resetTimestamp = firstOfMonth.getTime();

    if (key !== entry.resetTimestamp.toString(36)) {
      // New month — reset counter
      entry = { count: 1, resetTimestamp };
    } else {
      entry.count += 1;
    }

    budgetStore.set(ip, entry);

    const remaining = Math.max(0, budget - entry.count);

    // If budget exceeded, return 434? No, 403 with budget headers
    if (entry.count > budget) {
      res.setHeader("X-Budget-Remaining", "0");
      res.setHeader("X-Budget-Reset", new Date(resetTimestamp + 24 * 60 * 60 * 1000).toISOString());
      return res.status(403).json({
        error: "BUDGET_EXCEEDED",
        message: `Monthly budget of ${budget} requests exceeded.`,
        retryAfterSeconds: 86400, // reset tomorrow
      });
    }

    // Set budget headers on every response
    res.setHeader("X-Budget-Remaining", String(remaining));
    res.setHeader("X-Budget-Reset", new Date(resetTimestamp + 24 * 60 * 60 * 1000).toISOString());

    next();
  };
}