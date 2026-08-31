/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * nmap tool adapter. Validates params, builds a safe argument vector, and
 * parses the raw output into structured open-port findings. Only the TCP
 * Connect scan (-sT) is used so the container needs no raw-socket capabilities
 * (all Linux caps are dropped by the sandbox).
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";
import { DEFAULT_RESOURCE_LIMITS } from "./types";

export const NmapParamsSchema = z.object({
  ports: z
    .string()
    .regex(/^[0-9,-]+$/, "ports must be digits, commas and dashes only")
    .max(100)
    .optional()
    .default("1-1000"),
  serviceDetection: z.boolean().optional().default(false),
  timing: z.number().int().min(0).max(5).optional().default(4),
});

export type NmapParams = z.infer<typeof NmapParamsSchema>;

export const NMAP_TOOL_ID = "nmap";
export const nmapImage = () => process.env.NMAP_IMAGE || "instrumentisto/nmap:latest";

/** Build a sandbox run request for an nmap TCP connect scan. */
export function buildNmapRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = NmapParamsSchema.parse(rawParams ?? {});
  const args = ["-sT", `-T${params.timing}`, "-p", params.ports];
  if (params.serviceDetection) args.push("-sV");
  args.push(target);
  return {
    toolId: NMAP_TOOL_ID,
    target,
    args,
    image: nmapImage(),
    params: { ...params },
  };
}

export interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
}

/** Parse `PORT STATE SERVICE` rows (e.g. "22/tcp open ssh") from nmap output. */
export function parseNmapOutput(raw: string): NmapPort[] {
  const ports: NmapPort[] = [];
  const re = /^(\d{1,5})\/(tcp|udp)\s+(\S+)\s+(\S+)/;
  for (const line of raw.split(/\r?\n/)) {
    const m = re.exec(line.trim());
    if (m) {
      ports.push({
        port: Number(m[1]),
        protocol: m[2],
        state: m[3],
        service: m[4],
      });
    }
  }
  return ports;
}

/** Enrich a raw nmap ToolRunResult with parsed open-port findings. */
export function summarizeNmapResult(result: ToolRunResult): ToolRunResult {
  const openPorts = parseNmapOutput(result.rawOutput);
  return {
    ...result,
    structuredData: {
      ...result.structuredData,
      openPorts,
      openPortCount: openPorts.filter((p) => p.state === "open").length,
    },
  };
}

/** Registry descriptor for the nmap adapter. */
export const nmapDescriptor: ToolDescriptor = {
  id: NMAP_TOOL_ID,
  name: "Nmap Port & Service Scanner",
  version: "1.0.0",
  description:
    "Authorized TCP connect port/service discovery. Uses -sT only, so the " +
    "container needs no raw-socket capability and all Linux caps stay dropped.",
  capabilities: ["port-discovery", "service-detection"],
  inputSchema: NmapParamsSchema,
  outputSchemaHint: '{ openPorts: [{ port, protocol, state, service }], openPortCount: number }',
  permissions: ["network:scan"],
  riskLevel: "MEDIUM",
  timeoutMs: 60_000,
  resourceLimits: DEFAULT_RESOURCE_LIMITS,
  sandboxRequired: true,
  needsNetwork: true,
  get image() {
    return nmapImage();
  },
};

/** The executable nmap adapter registered in the tool registry. */
export const nmapAdapter: ToolAdapter = {
  descriptor: nmapDescriptor,
  build: buildNmapRequest,
  parse: summarizeNmapResult,
};
