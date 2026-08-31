/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Internal event bus (§26). Typed, in-process, and observable: every event
 * carries its own id plus the trace id of the work that produced it, so a whole
 * mission can be reconstructed from the stream.
 *
 * Deliberately synchronous and best-effort — a misbehaving subscriber must
 * never break a security decision or a tool run, so listener errors are
 * swallowed and recorded rather than propagated.
 */

import crypto from "crypto";

export type PlatformEventType =
  | "TASK_CREATED"
  | "TASK_STARTED"
  | "AGENT_STARTED"
  | "AGENT_COMPLETED"
  | "TOOL_REQUESTED"
  | "TOOL_APPROVED"
  | "TOOL_DENIED"
  | "TOOL_STARTED"
  | "TOOL_COMPLETED"
  | "TOOL_NOT_AVAILABLE"
  | "FINDING_CREATED"
  | "FINDING_VALIDATED"
  | "REMEDIATION_CREATED"
  | "TEST_STARTED"
  | "TEST_COMPLETED"
  | "TASK_FAILED"
  | "TASK_COMPLETED";

export interface PlatformEvent {
  eventId: string;
  traceId: string;
  type: PlatformEventType;
  timestamp: string;
  /** Correlation ids, all optional so any layer can emit. */
  taskId?: string;
  runId?: string;
  agentId?: string;
  toolId?: string;
  projectId?: string;
  target?: string;
  /** Non-sensitive detail. Never put raw tool output or secrets here. */
  detail?: string;
  data?: Record<string, unknown>;
}

export type EventListener = (event: PlatformEvent) => void;

const listeners = new Set<EventListener>();
const recent: PlatformEvent[] = [];
const MAX_RECENT = 500;

/** Subscribe to the stream. Returns an unsubscribe function. */
export function onEvent(listener: EventListener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Emit an event. Returns the materialized record (with ids and timestamp). */
export function emitEvent(
  type: PlatformEventType,
  fields: Omit<PlatformEvent, "eventId" | "type" | "timestamp" | "traceId"> & {
    traceId?: string;
  } = {},
): PlatformEvent {
  const event: PlatformEvent = {
    eventId: `evt_${crypto.randomUUID()}`,
    traceId: fields.traceId ?? `trc_${crypto.randomUUID()}`,
    type,
    timestamp: new Date().toISOString(),
    ...fields,
  };

  recent.unshift(event);
  if (recent.length > MAX_RECENT) recent.pop();

  for (const l of listeners) {
    try {
      l(event);
    } catch {
      /* a subscriber must never break the emitter */
    }
  }
  return event;
}

/** Recent events, newest first. Optionally filtered by trace id. */
export function listEvents(opts: { traceId?: string; limit?: number } = {}): PlatformEvent[] {
  const limit = Math.min(Math.max(opts.limit ?? 100, 1), MAX_RECENT);
  const source = opts.traceId ? recent.filter((e) => e.traceId === opts.traceId) : recent;
  return source.slice(0, limit);
}

/** Test helper: drop all subscribers and buffered events. */
export function resetEvents(): void {
  listeners.clear();
  recent.length = 0;
}
