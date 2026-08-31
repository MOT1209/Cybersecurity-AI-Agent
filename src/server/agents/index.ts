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

export * from "./base";
export * from "./types";
export * from "./manager";
export * from "./recon/agent";
export * from "./web/agent";
export * from "./code/agent";

agentManager.register(reconAgent);
agentManager.register(webAgent);
agentManager.register(codeAgent);
