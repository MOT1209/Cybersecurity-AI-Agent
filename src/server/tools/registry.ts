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
  };
}

const ADAPTERS: ToolAdapter[] = [nmapAdapter, subfinderAdapter, nucleiAdapter];

const DECLARED: ToolDescriptor[] = [
  declared("semgrep", "Semgrep SAST Code Engine", "LOW", ["static-analysis"], "Static application security testing. Adapter not implemented yet.", false),
  declared("trivy", "Trivy Container & FS Scanner", "LOW", ["container-scan", "dependency-scan", "fs-scan"], "Container/dependency/filesystem scanning. Adapter not implemented yet.", false),
  declared("zap", "OWASP ZAP Dynamic API Tester", "HIGH", ["dast"], "Dynamic web application testing. Adapter not implemented yet."),
  declared("prowler", "Prowler Cloud Security Auditing", "MEDIUM", ["cloud-audit"], "Cloud posture auditing. Adapter not implemented yet."),
  declared("volatility", "Volatility Memory Forensics Engine", "LOW", ["memory-forensics"], "Memory image forensics. Adapter not implemented yet.", false),
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
