/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Agents barrel + registration. Each agent does one thing, runs its tools
 * through the gateway-guarded sandbox, and reasons over the results via the LLM
 * layer with a local fallback. Registration happens here so the orchestrator
 * only ever talks to the Agent Manager.
 */

import { agentManager } from "./manager";
import { reconAgent } from "./recon/agent";
import { webAgent } from "./web/agent";
import { codeAgent } from "./code/agent";
import { validationAgent } from "./validation/agent";
import { remediationAgent } from "./remediation/agent";
import { reportingAgent } from "./reporting/agent";
import { testingAgent } from "./testing/agent";

export * from "./base";
export * from "./types";
export * from "./manager";
export * from "./recon/agent";
export * from "./web/agent";
export * from "./code/agent";
export * from "./validation/agent";
export * from "./remediation/agent";
export * from "./reporting/agent";
export * from "./testing/agent";

agentManager.register(reconAgent);
agentManager.register(webAgent);
agentManager.register(codeAgent);
agentManager.register(validationAgent);
agentManager.register(remediationAgent);
agentManager.register(reportingAgent);
agentManager.register(testingAgent);
