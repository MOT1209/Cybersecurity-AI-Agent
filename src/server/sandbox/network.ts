/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sandbox network policy (§16). Tool containers run on a dedicated, internal
 * user-defined bridge rather than sharing the host's default `bridge`.
 *
 * Two modes:
 *   "isolated" (default) — a dedicated network created by this module. Attach
 *       lab target containers to the same network so tools can reach them while
 *       staying off the default bridge with every other container on the host.
 *   "none" — no network at all. Correct for offline tools (SAST, filesystem
 *       scanning) that must never be able to reach anything.
 *
 * SANDBOX_ALLOW_EGRESS=true drops the `internal` flag so the network can reach
 * the outside world. It is off by default: a scanner that cannot route off the
 * lab network cannot scan the internet by accident.
 */

import type DockerodeType from "dockerode";

export type NetworkMode = "isolated" | "none";

export const SANDBOX_NETWORK_NAME =
  process.env.SANDBOX_NETWORK_NAME || "cyberguard_sandbox";

export function allowEgress(): boolean {
  return String(process.env.SANDBOX_ALLOW_EGRESS || "").trim().toLowerCase() === "true";
}

/** Resolve the network a given tool run should use. */
export function networkModeFor(toolNeedsNetwork: boolean): NetworkMode {
  return toolNeedsNetwork ? "isolated" : "none";
}

/**
 * Ensure the dedicated sandbox network exists, returning the name Docker should
 * be given. Creation is idempotent and races are tolerated (a concurrent
 * creation surfaces as "already exists", which is success for our purposes).
 */
export async function ensureSandboxNetwork(docker: DockerodeType): Promise<string> {
  const name = SANDBOX_NETWORK_NAME;
  try {
    await docker.getNetwork(name).inspect();
    return name;
  } catch {
    /* not present yet */
  }
  try {
    await docker.createNetwork({
      Name: name,
      Driver: "bridge",
      // `Internal` blocks routing to the outside world entirely.
      Internal: !allowEgress(),
      CheckDuplicate: true,
      Labels: { "cyberguard.managed": "true" },
    });
  } catch (err) {
    const msg = (err as Error).message || "";
    if (!/already exists/i.test(msg)) throw err;
  }
  return name;
}
