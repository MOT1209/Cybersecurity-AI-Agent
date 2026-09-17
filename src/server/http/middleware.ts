/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * HTTP middleware shared by every route group: API-key authentication to a
 * principal, the global and AI rate limiters, and the small request helpers
 * the handlers use. Kept here rather than in server.ts so the route modules
 * stay free of middleware plumbing.
 */

import type { NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import { incrementDailyExecution } from "../tools/registry";
import type { Principal, Role } from "../security/principal";

// Monthly budget guard lives in core/budget; re-exported here so the app
// assembly imports every global guard from this one module.
export { enforceMonthlyBudget } from "../core/budget";

/** Maximum tool executions per IP per day. Set to `0` or omit to disable. */
export const MAX_TOOL_EXECUTIONS_PER_DAY = Number(process.env.MAX_TOOL_EXECUTIONS_PER_DAY) || 0;

/**
 * Execution limit enforcement — after budget and auth, checks per-IP daily
 * tool execution cap. Increments the counter on each allowed request so the
 * limit is tight.
 */
export function enforcementLimitHandler(message: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = (req as Request & { ip?: string }).ip || "unknown";

    // Count this request toward the daily exec limit
    const path = req.path;
    // Extract tool ID from path if possible (e.g., /api/tools/execute/:id)
    const toolIdMatch = path.match(/\/api\/tools\/execute\/([^/]+)/);
    const toolId = toolIdMatch ? toolIdMatch[1] : "unknown";

    incrementDailyExecution(ip, toolId);

    if (MAX_TOOL_EXECUTIONS_PER_DAY <= 0) {
      return next();
    }

    // We need to check the count after incrementing; the store tracks per-ip per-tool
    const ipStore = (global as any).dailyExecStore?.get(ip);
    const count = ipStore ? ipStore.get(toolId) : 1;

    if (count > MAX_TOOL_EXECUTIONS_PER_DAY) {
      const _resetTime = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      return res.status(429).json({
        error: "DAILY_EXECUTION_LIMIT_EXCEEDED",
        message: `${message} Please retry after 24 hours.`,
        retryAfterSeconds: 86400,
      });
    }

    next();
  };
}

import {
  resolvePrincipal,
  principalsConfigured,
  hasRole,
  SHARED_KEY_PRINCIPAL,
  ANONYMOUS_PRINCIPAL,
} from "../security/principal";

/**
 * Constant-time API key comparison. Both sides are hashed first so the
 * comparison operates on equal-length buffers — timingSafeEqual throws on a
 * length mismatch, and comparing raw keys would leak the expected length.
 */
export const safeKeyEqual = (provided: string, expected: string): boolean => {
  const a = crypto.createHash("sha256").update(provided).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
};

function rateLimitHandler(message: string) {
  return (req: Request, res: Response) => {
    const resetTime = (req as Request & { rateLimit?: { resetTime?: Date } }).rateLimit?.resetTime;
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((resetTime ? resetTime.getTime() - Date.now() : 15 * 60 * 1000) / 1000)
    );
    res.status(429).json({
      error: "TOO_MANY_REQUESTS",
      message: `${message} Please retry after ${retryAfterSeconds} seconds.`,
      retryAfterSeconds,
    });
  };
}

/** Global Rate Limiter: 60 requests / 15 minutes per IP on all /api/* routes. */
export function createGlobalApiLimiter() {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    validate: {
      xForwardedForHeader: false,
      forwardedHeader: false,
      trustProxy: false,
    },
    handler: rateLimitHandler("Global rate limit exceeded (60 requests / 15 min)."),
  });
}

/** Strict Gemini Rate Limiter: 15 requests / 15 minutes per IP. */
export function createGeminiAiLimiter() {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    validate: {
      xForwardedForHeader: false,
      forwardedHeader: false,
      trustProxy: false,
    },
    handler: rateLimitHandler("AI token consumption rate limit exceeded (15 requests / 15 min)."),
  });
}

/**
 * Authentication. Resolves the caller to a Principal so authorization can be
 * about identity and roles rather than mere possession of a shared key.
 *
 * Precedence:
 *   1. API_PRINCIPALS — per-key identities with roles (preferred).
 *   2. APP_ACCESS_KEY — legacy shared key. Grants operator/viewer but NOT
 *      approver: a key everyone shares is not a person, so it must not be
 *      able to satisfy a human-approval requirement.
 *   3. Neither configured — open local development.
 */
export function apiKeyAuthMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.path === "/health" || req.path === "/api/health") {
    return next();
  }
  const providedKey = req.header("x-api-key");
  const principalRequest = req as Request & { principal?: Principal };

  if (principalsConfigured()) {
    const principal = resolvePrincipal(providedKey);
    if (!principal) {
      return res.status(401).json({
        error: "UNAUTHORIZED",
        message: "Invalid or missing API key in 'x-api-key' header.",
      });
    }
    principalRequest.principal = principal;
    return next();
  }

  const expectedKey = process.env.APP_ACCESS_KEY;
  if (!expectedKey) {
    principalRequest.principal = ANONYMOUS_PRINCIPAL;
    return next();
  }
  if (!providedKey || !safeKeyEqual(providedKey, expectedKey)) {
    return res.status(401).json({
      error: "UNAUTHORIZED",
      message: "Invalid or missing API key in 'x-api-key' header.",
    });
  }
  principalRequest.principal = SHARED_KEY_PRINCIPAL;
  next();
}

export function principalOf(req: Request): Principal {
  return (req as Request & { principal?: Principal }).principal ?? ANONYMOUS_PRINCIPAL;
}

export function callerHasRole(req: Request, role: Role): boolean {
  return hasRole(principalOf(req), role);
}

/**
 * Role gate for mutating/executing routes. Call AFTER input validation so a
 * malformed request still gets 400 (not a misleading 403), and check the
 * authenticated principal — never a name from the body.
 */
export function requireRole(req: Request, res: Response, role: Role): boolean {
  if (callerHasRole(req, role)) return true;
  const principal = principalOf(req);
  res.status(403).json({
    error: "FORBIDDEN",
    message:
      `Principal "${principal.id}" does not hold the "${role}" role. ` +
      "Configure per-key identities via API_PRINCIPALS.",
  });
  return false;
}