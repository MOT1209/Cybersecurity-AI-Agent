/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tool plugin contract (§9). A ToolDescriptor is the registry record; a
 * ToolAdapter is the executable implementation. A descriptor without an adapter
 * is a *declared* tool that cannot run for real — the registry says so
 * explicitly instead of silently simulating it.
 */

import type { ZodTypeAny } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ResourceLimits {
  cpus: number;
  memoryMb: number;
  pids: number;
}

export const DEFAULT_RESOURCE_LIMITS: ResourceLimits = {
  cpus: 1,
  memoryMb: 512,
  pids: 256,
};

export interface ToolDescriptor {
  id: string;
  name: string;
  /** Adapter version, independent of the underlying binary version. */
  version: string;
  description: string;
  capabilities: string[];
  /** Zod schema for the tool's params. */
  inputSchema: ZodTypeAny;
  /** Human-readable shape of `structuredData` this tool produces. */
  outputSchemaHint: string;
  /** Coarse permissions this tool needs, e.g. ["network:scan"]. */
  permissions: string[];
  riskLevel: RiskLevel;
  timeoutMs: number;
  resourceLimits: ResourceLimits;
  /** When true, the tool may only run inside a real isolated sandbox. */
  sandboxRequired: boolean;
  /**
   * False for tools that must never reach the network (SAST, filesystem
   * scanning). Those run with no network interface at all.
   */
  needsNetwork: boolean;
  /** Container image used by the sandbox executor, when applicable. */
  image?: string;
}

export interface ToolAdapter {
  readonly descriptor: ToolDescriptor;
  /** Validate + normalize raw params. Throws ZodError on invalid input. */
  build(target: string, rawParams: unknown): ToolRunRequest;
  /** Enrich a raw run result with parsed, structured findings. */
  parse(result: ToolRunResult): ToolRunResult;
}
