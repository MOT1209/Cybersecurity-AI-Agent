/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sandbox execution contract. A ToolExecutor runs a single security tool in an
 * isolated environment and returns a normalized result. Two implementations
 * exist: LocalSimExecutor (deterministic simulation, no Docker required) and
 * DockerExecutor (real containerized execution via dockerode).
 */

export interface ToolRunRequest {
  /** Logical tool id, e.g. "nmap". */
  toolId: string;
  /** Authorized target (already passed through the security gateway). */
  target: string;
  /** Argv for the tool inside the container, e.g. ["-sT", "-p", "1-1000"]. */
  args: string[];
  /** Container image to run (DockerExecutor only). */
  image?: string;
  /** Hard wall-clock limit in ms. Defaults to 60_000. */
  timeoutMs?: number;
  /** Free-form params echoed back into structuredData for traceability. */
  params?: Record<string, unknown>;
  /** Per-tool resource ceiling. Falls back to the sandbox defaults. */
  resourceLimits?: { cpus: number; memoryMb: number; pids: number };
  /** False for offline tools, which are run with no network at all. */
  needsNetwork?: boolean;
  /** Host path to bind read-only at /workspace. Already containment-checked. */
  workspaceHostPath?: string;
}

export interface SandboxInfo {
  containerId: string;
  isolated: boolean;
  cpuLimit: string;
  memoryLimit: string;
  network: string;
  /** True when the container could not route off the sandbox network. */
  egressBlocked: boolean;
  /** Writable scratch space, mounted as tmpfs. Root filesystem is read-only. */
  workspace: string;
  /** "docker" for real execution, "local-sim" for the simulated fallback. */
  mode: "docker" | "local-sim";
}

export interface ToolRunResult {
  toolId: string;
  target: string;
  timestamp: string;
  status: "SUCCESS" | "FAILED" | "TIMEOUT";
  exitCode: number;
  sandbox: SandboxInfo;
  rawOutput: string;
  structuredData: Record<string, unknown>;
}

export interface ToolExecutor {
  /** Stable id: "docker" | "local-sim". */
  readonly id: SandboxInfo["mode"];
  /** Whether this executor can run right now (e.g. Docker daemon reachable). */
  isAvailable(): Promise<boolean>;
  /** Execute the tool and return a normalized result. Never throws for tool
   * failure — a non-zero exit / timeout is reported via status/exitCode. */
  run(req: ToolRunRequest): Promise<ToolRunResult>;
}

export const DEFAULT_TIMEOUT_MS = 60_000;
