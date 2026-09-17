/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Run modes — the platform's operating posture, selected per engagement (and
 * switchable over the API). A mode decides which enforcement layers are
 * active, not what the code is capable of:
 *
 *   - learn:   nothing executes and no target is touched; the platform teaches
 *              and reasons only.
 *   - lab:     everything runs exclusively against the isolated, locally-hosted
 *              labs. Container EGRESS is a separate operator switch
 *              (SANDBOX_ALLOW_EGRESS), with these labs defaulting open per the
 *              platform decision.
 *   - execute: authorized engagements — standard gateway and approvals for
 *              HIGH/CRITICAL only.
 *   - pair:    an approve-at-every-step companion: no tool executes without a
 *              fresh human decision.
 *
 * The resolver and the per-mode gates are pure and exhaustively testable; the
 * store at the bottom holds the process-wide default so `/api/runtime/mode`
 * can read and switch it with one validated call.
 */

export const RUN_MODES = ["learn", "lab", "execute", "pair"] as const;
export type RunMode = (typeof RUN_MODES)[number];

export const DEFAULT_RUN_MODE: RunMode = "execute";

export interface RunGate {
  /** May a tool's run reach a network target at all? */
  egressAllowed: boolean;
  /** Must EVERY tool execution pass a fresh human approval? */
  approvalEveryStep: boolean;
  /** May the platform execute tools/sandbox, or is this mode read/teach only? */
  executionAllowed: boolean;
  /** Is the mode restricted to the locally-hosted labs only? */
  labOnly: boolean;
  /** Human-readable statement of what the mode means. */
  purpose: string;
}

/**
 * Deterministic, immutable gate per mode. The HTTP layer reads these; the
 * agent runtime can consult them through the run context.
 */
export const RUN_GATES: Record<RunMode, RunGate> = {
  learn: {
    egressAllowed: false,
    approvalEveryStep: false,
    executionAllowed: false,
    labOnly: false,
    purpose: "Nothing executes and no target is touched; the platform teaches, reviews and reasons only.",
  },
  lab: {
    egressAllowed: true,
    approvalEveryStep: false,
    executionAllowed: true,
    labOnly: true,
    purpose: "Everything runs exclusively inside the isolated labs; engagement-scoped, never a production asset.",
  },
  execute: {
    egressAllowed: true,
    approvalEveryStep: false,
    executionAllowed: true,
    labOnly: false,
    purpose: "Authorized engagements: the standard security gateway plus human approval for HIGH/CRITICAL risk.",
  },
  pair: {
    egressAllowed: true,
    approvalEveryStep: true,
    executionAllowed: true,
    labOnly: false,
    purpose: "A human approves every tool run before it may execute; the platform proceeds step by step.",
  },
};

export function isRunMode(value: unknown): value is RunMode {
  return typeof value === "string" && (RUN_MODES as readonly string[]).includes(value);
}

/**
 * Validate a caller-supplied mode string. Anything unknown, malformed or not a
 * mode falls back to the given default — a bad value must never fail-open into
 * a more permissive mode or crash the route.
 */
export function resolveRunMode(value: unknown, fallback: RunMode = DEFAULT_RUN_MODE): RunMode {
  return isRunMode(value) ? value : fallback;
}

export function gateFor(mode: RunMode): RunGate {
  return RUN_GATES[mode];
}

// --- Process-wide default-mode store --------------------------------------

let activeRunMode: RunMode = DEFAULT_RUN_MODE;

/** Current platform-wide default. Per-mission callers may override it. */
export function getRunMode(): RunMode {
  return activeRunMode;
}

/** Switch the platform-wide default. Validated upstream before calling. */
export function setRunMode(mode: RunMode): RunMode {
  activeRunMode = mode;
  return activeRunMode;
}