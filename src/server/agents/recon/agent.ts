/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Recon agent: runs a real (or simulated) nmap scan through the sandbox, parses
 * open ports, then asks the LLM to summarize the attack surface — with a
 * deterministic local fallback derived from the parsed ports so it works with
 * no model configured.
 */

import { z } from "zod";
import { BaseAgent } from "../base";
import type { AgentResult } from "../base";
import type { AgentDescriptor, AgentRunContext } from "../types";
import { executeTool } from "../../sandbox/index";
import { buildNmapRequest, summarizeNmapResult, NMAP_TOOL_ID, nmapImage } from "../../tools/nmap";
import type { NmapPort } from "../../tools/nmap";
import { RECON_INSTRUCTION, RECON_SCHEMA_HINT } from "./prompts";

export interface ReconInput {
  target: string;
  params?: unknown;
  projectId?: string;
}

export interface ReconAnalysis {
  hostRole: string;
  notableServices: string[];
  riskObservations: string[];
  nextSteps: string[];
}

export interface ReconData {
  target: string;
  openPorts: NmapPort[];
  openPortCount: number;
  sandboxMode: string;
  analysis: ReconAnalysis;
}

export const ReconInputSchema = z.object({
  target: z.string().min(1).max(500),
  params: z.unknown().optional(),
  projectId: z.string().max(100).optional(),
});

export const ReconOutputSchema = z.object({
  target: z.string(),
  openPorts: z.array(
    z.object({
      port: z.number(),
      protocol: z.string(),
      state: z.string(),
      service: z.string(),
    }),
  ),
  openPortCount: z.number(),
  sandboxMode: z.string(),
  analysis: z.object({
    hostRole: z.string(),
    notableServices: z.array(z.string()),
    riskObservations: z.array(z.string()),
    nextSteps: z.array(z.string()),
  }),
});

export const reconDescriptor: AgentDescriptor = {
  id: "recon",
  name: "Reconnaissance Agent",
  description:
    "Discovers the network attack surface of an authorized target by running " +
    "a sandboxed nmap TCP connect scan and reasoning over the parsed ports.",
  capabilities: ["asset-discovery", "service-discovery", "port-discovery"],
  skills: ["reconnaissance.service-discovery"],
  allowedTools: ["nmap"],
  permissions: ["tool:execute", "scope:read"],
  riskLevel: "MEDIUM",
  timeoutMs: 90_000,
  inputSchema: ReconInputSchema,
  outputSchema: ReconOutputSchema,
  memoryPolicy: { maxTasks: 3, persistRawOutput: false },
};

export class ReconAgent extends BaseAgent {
  readonly id = "recon";

  describe(): AgentDescriptor {
    return reconDescriptor;
  }

  async run(input: ReconInput, ctx?: AgentRunContext): Promise<AgentResult<ReconData>> {
    const parsed = ReconInputSchema.parse(input);
    input = { ...parsed, params: input.params } as ReconInput;
    if (ctx?.projectId && !input.projectId) input.projectId = ctx.projectId;
    this.remember(input);

    const req = buildNmapRequest(input.target, input.params);
    const rawResult = await executeTool({
      toolId: NMAP_TOOL_ID,
      target: input.target,
      args: req.args,
      image: nmapImage(),
      params: req.params,
      projectId: input.projectId,
      actor: "ReconAgent",
    });
    const result = summarizeNmapResult(rawResult);
    this.logToolCall(result);

    const openPorts = (result.structuredData.openPorts as NmapPort[]) ?? [];
    const openPortCount = (result.structuredData.openPortCount as number) ?? 0;

    const localFallback = (): ReconAnalysis => ({
      hostRole: openPorts.some((p) => [80, 443, 8080].includes(p.port))
        ? "Web-facing host"
        : openPorts.length
          ? "Networked service host"
          : "No open ports observed",
      notableServices: openPorts
        .filter((p) => p.state === "open")
        .map((p) => `${p.port}/${p.protocol} ${p.service}`),
      riskObservations: openPorts.some((p) => p.port === 23)
        ? ["Telnet (23) exposed — cleartext protocol"]
        : [],
      nextSteps: openPorts.some((p) => [80, 443, 8080].includes(p.port))
        ? ["Run the Web agent (nuclei) against exposed HTTP services"]
        : ["Enumerate service versions with -sV"],
    });

    const reasoning = await this.reason<ReconAnalysis>(
      result.rawOutput,
      RECON_INSTRUCTION,
      RECON_SCHEMA_HINT,
      localFallback,
    );

    return {
      agentId: this.id,
      summary: `Recon on ${input.target}: ${openPortCount} open port(s) via ${result.sandbox.mode} sandbox.`,
      data: {
        target: input.target,
        openPorts,
        openPortCount,
        sandboxMode: result.sandbox.mode,
        analysis: reasoning.data,
      },
      toolCalls: this.toolCalls,
      provider: reasoning.provider,
      fallback: reasoning.fallback,
    };
  }
}

export const reconAgent = new ReconAgent();
