/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Recon agent: runs a real (or simulated) nmap scan through the sandbox, parses
 * open ports, then asks the LLM to summarize the attack surface — with a
 * deterministic local fallback derived from the parsed ports so it works with
 * no model configured.
 */

import { BaseAgent } from "../base";
import type { AgentResult } from "../base";
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

export class ReconAgent extends BaseAgent {
  readonly id = "recon";

  async run(input: ReconInput): Promise<AgentResult<ReconData>> {
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
