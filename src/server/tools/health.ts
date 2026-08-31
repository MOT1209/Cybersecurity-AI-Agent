/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tool health system (§32). Reports the ACTUAL state of every registered tool.
 *
 * "Installed" here means the container image is present on the Docker host, as
 * verified by an image inspect — not that the tool appears in a catalog. When
 * the sandbox is unreachable the health check says so instead of guessing, and
 * a declared-only tool is never reported as usable.
 */

import { DockerExecutor } from "../sandbox/docker";
import { resolveSandboxMode } from "../sandbox/index";
import { listTools, getToolDescriptor, hasAdapter } from "./registry";

export type ToolHealthState = "READY" | "SIMULATED_ONLY" | "NOT_INSTALLED" | "NOT_IMPLEMENTED" | "SANDBOX_UNAVAILABLE";

export interface ToolHealth {
  toolId: string;
  name: string;
  /** Adapter version. Null when no adapter exists. */
  adapterVersion: string | null;
  state: ToolHealthState;
  /** Adapter implemented in this codebase. */
  implemented: boolean;
  /** Container image present on the Docker host (null = could not check). */
  imagePresent: boolean | null;
  image?: string;
  sandboxAvailable: boolean;
  sandboxRequired: boolean;
  riskLevel: string;
  /** Plain-language reason for the state. Always populated. */
  reason: string;
  checkedAt: string;
}

const docker = new DockerExecutor();

/**
 * Health for a single tool. Performs a real image inspect when Docker is
 * reachable; never claims installation it did not verify.
 */
export async function checkToolHealth(toolId: string): Promise<ToolHealth> {
  const d = getToolDescriptor(toolId);
  const checkedAt = new Date().toISOString();
  if (!d) {
    return {
      toolId,
      name: toolId,
      adapterVersion: null,
      state: "NOT_IMPLEMENTED",
      implemented: false,
      imagePresent: null,
      sandboxAvailable: false,
      sandboxRequired: true,
      riskLevel: "UNKNOWN",
      reason: "Tool is not registered.",
      checkedAt,
    };
  }

  const implemented = hasAdapter(toolId);
  const mode = resolveSandboxMode();
  const sandboxAvailable = mode === "simulate" ? false : await docker.isAvailable();

  let imagePresent: boolean | null = null;
  if (sandboxAvailable && d.image) {
    imagePresent = await docker.hasImage(d.image);
  }

  const base = {
    toolId,
    name: d.name,
    adapterVersion: implemented ? d.version : null,
    implemented,
    imagePresent,
    image: d.image,
    sandboxAvailable,
    sandboxRequired: d.sandboxRequired,
    riskLevel: d.riskLevel,
    checkedAt,
  };

  if (!implemented) {
    return { ...base, state: "NOT_IMPLEMENTED", reason: "Declared in the registry, but no adapter is implemented yet." };
  }
  if (mode === "simulate") {
    return { ...base, state: "SIMULATED_ONLY", reason: 'SANDBOX_MODE=simulate — this tool will produce clearly-labelled simulated output, not real results.' };
  }
  if (!sandboxAvailable) {
    return { ...base, state: "SANDBOX_UNAVAILABLE", reason: "The Docker sandbox is unreachable, so this tool cannot execute." };
  }
  if (d.image && imagePresent === false) {
    return { ...base, state: "NOT_INSTALLED", reason: `Image "${d.image}" is not present on the Docker host. It will be pulled on first run.` };
  }
  return { ...base, state: "READY", reason: "Adapter implemented, sandbox reachable, image present." };
}

/** Health for every registered tool. */
export async function checkAllToolHealth(): Promise<ToolHealth[]> {
  return Promise.all(listTools().map((t) => checkToolHealth(t.descriptor.id)));
}
