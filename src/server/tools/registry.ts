/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tool registry. The single source of truth for which tools exist, what they
 * are allowed to do, and — critically — whether each one has a real adapter.
 *
 * Two distinct states, never conflated:
 *   registered + implemented  → can execute for real
 *   registered, no adapter    → DECLARED ONLY; execution raises
 *                               ToolNotAvailableError unless the operator has
 *                               explicitly opted into simulation.
 * Anything not registered is denied outright (fail closed, §39).
 */

import { z } from "zod";
import type { ToolAdapter, ToolDescriptor, RiskLevel } from "./types";
import { DEFAULT_RESOURCE_LIMITS } from "./types";
import { nmapAdapter } from "./nmap";
import { subfinderAdapter } from "./subfinder";
import { nucleiAdapter } from "./nuclei";
import { semgrepAdapter } from "./semgrep";
import { trivyAdapter } from "./trivy";
import { volatilityAdapter } from "./volatility";
import { zapAdapter } from "./zap";
import { wfuzzAdapter } from "./wfuzz";
import { theHarvesterAdapter } from "./theharvester";
import { ctfrAdapter } from "./ctfr";
import { sqlmapAdapter } from "./sqlmap";
import { xsstrikeAdapter } from "./xsstrike";

/** Declared-but-unimplemented tools, surfaced honestly to the UI and API. */
function declared(
  id: string,
  name: string,
  riskLevel: RiskLevel,
  capabilities: string[],
  description: string,
  needsNetwork = true,
): ToolDescriptor {
  return {
    id,
    name,
    version: "0.0.0-unimplemented",
    description,
    capabilities,
    inputSchema: z.object({}).passthrough(),
    outputSchemaHint: "{}",
    permissions: [],
    riskLevel,
    timeoutMs: 60_000,
    resourceLimits: DEFAULT_RESOURCE_LIMITS,
    sandboxRequired: true,
    needsNetwork,
    targetKind: needsNetwork ? "network" : "filesystem",
    filesystemAccess: needsNetwork ? "none" : "workspace-ro",
  };
}

const ADAPTERS: ToolAdapter[] = [
  nmapAdapter,
  subfinderAdapter,
  nucleiAdapter,
  semgrepAdapter,
  trivyAdapter,
  volatilityAdapter,
  zapAdapter,
  wfuzzAdapter,
  theHarvesterAdapter,
  ctfrAdapter,
  sqlmapAdapter,
  xsstrikeAdapter,
];

const DECLARED: ToolDescriptor[] = [
  // Prowler stays declared-only: a cloud audit needs a credential channel and
  // a cloud-scope gateway branch, neither of which exists yet. Declaring the
  // gap here is the roadmap, not a promise.
  declared("prowler", "Prowler Cloud Security Auditing", "MEDIUM", ["cloud-audit"], "Cloud posture auditing. Adapter not implemented yet: blocked on a credential channel and cloud-scope authorization."),
];

const adapters = new Map<string, ToolAdapter>(ADAPTERS.map((a) => [a.descriptor.id, a]));
const descriptors = new Map<string, ToolDescriptor>([
  ...ADAPTERS.map((a) => [a.descriptor.id, a.descriptor] as const),
  ...DECLARED.map((d) => [d.id, d] as const),
]);

/** Register (or replace) a tool adapter at runtime. */
export function registerToolAdapter(adapter: ToolAdapter): void {
  adapters.set(adapter.descriptor.id, adapter);
  descriptors.set(adapter.descriptor.id, adapter.descriptor);
}

export function isToolRegistered(toolId: string): boolean {
  return descriptors.has(toolId);
}

export function getToolDescriptor(toolId: string): ToolDescriptor | undefined {
  return descriptors.get(toolId);
}

/** The executable adapter, or undefined when the tool is declared-only. */
export function getToolAdapter(toolId: string): ToolAdapter | undefined {
  return adapters.get(toolId);
}

export function hasAdapter(toolId: string): boolean {
  return adapters.has(toolId);
}

export interface ToolRegistryEntry {
  descriptor: Omit<ToolDescriptor, "inputSchema">;
  implemented: boolean;
}

/** Per-IP daily execution counter for the special execution limit. */
const dailyExecStore = new Map<string, Map<string, number>>(); // ip -> toolId -> count

export function incrementDailyExecution(ip: string, toolId: string): void {
  const ipStore = dailyExecStore.get(ip) ?? new Map<string, number>();
  const count = (ipStore.get(toolId) ?? 0) + 1;
  ipStore.set(toolId, count);
  dailyExecStore.set(ip, ipStore);
}

/** Reset daily execution counters (call e.g. at midnight or on server restart). */
export function resetDailyCounters(): void {
  dailyExecStore.clear();
}

/** Registry listing for the API/UI. Zod schemas are not serializable, so the
 *  input schema is omitted rather than emitted as `{}`. */
export function listTools(): ToolRegistryEntry[] {
  return [...descriptors.values()]
    .map(({ inputSchema: _inputSchema, ...rest }) => ({
      descriptor: rest,
      implemented: adapters.has(rest.id),
    }))
    .sort((a, b) => a.descriptor.id.localeCompare(b.descriptor.id));
}
