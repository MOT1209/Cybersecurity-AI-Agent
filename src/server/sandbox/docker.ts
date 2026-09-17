/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Real containerized execution via dockerode. `dockerode` is imported
 * dynamically so the app never crashes at load time when the package or the
 * Docker daemon is absent — availability is probed at runtime and the caller
 * falls back to LocalSimExecutor.
 *
 * Isolation posture per container:
 *   - read-only root filesystem, all Linux capabilities dropped, no-new-privileges
 *   - 1 CPU / 512MB memory / 256 pids ceiling
 *   - hard wall-clock timeout (container killed on expiry)
 *   - network configurable via SANDBOX_DOCKER_NETWORK (default "bridge")
 */

import type DockerodeType from "dockerode";
import type { Container } from "dockerode";
import type { ToolExecutor, ToolRunRequest, ToolRunResult, SandboxInfo } from "./types";
import { DEFAULT_TIMEOUT_MS } from "./types";
import { ensureSandboxNetwork, allowEgress, networkModeFor } from "./network";
import { CONTAINER_WORKSPACE } from "../security/workspace";

type DockerCtor = new () => DockerodeType;

/** Load dockerode lazily; returns null if the package cannot be imported. */
async function loadDocker(): Promise<DockerodeType | null> {
  try {
    const mod: any = await import("dockerode");
    const Docker: DockerCtor = mod.default ?? mod;
    return new Docker();
  } catch {
    return null;
  }
}

async function pullImage(docker: DockerodeType, image: string): Promise<void> {
  const stream: NodeJS.ReadableStream = await (docker as any).pull(image);
  await new Promise<void>((resolve, reject) => {
    (docker as any).modem.followProgress(stream, (err: unknown) =>
      err ? reject(err) : resolve(),
    );
  });
}

/**
 * Make an image available locally, pulling once when it is absent. Shared by
 * the tool executor and the lab readiness probe (§2.7) so both behave the same
 * way rather than each having their own idea of when to pull.
 */
export async function ensureImagePresent(docker: DockerodeType, image: string): Promise<void> {
  try {
    await docker.getImage(image).inspect();
    return;
  } catch {
    /* not present locally */
  }
  await pullImage(docker, image);
}

export class DockerExecutor implements ToolExecutor {
  readonly id = "docker" as const;
  private cachedDocker: DockerodeType | null | undefined;
  /** Short-lived availability cache: probing on every tool call is wasteful. */
  private availability?: { value: boolean; expiresAt: number };

  private async getDocker(): Promise<DockerodeType | null> {
    if (this.cachedDocker === undefined) {
      this.cachedDocker = await loadDocker();
    }
    return this.cachedDocker;
  }

  /**
   * Probe the daemon with a hard deadline. Without one, an unreachable socket
   * can hang for the OS connect timeout and stall every tool request behind it.
   */
  async isAvailable(): Promise<boolean> {
    if (this.availability && Date.now() < this.availability.expiresAt) {
      return this.availability.value;
    }
    const ttlMs = Number(process.env.SANDBOX_DOCKER_PROBE_TTL_MS) || 30_000;
    const remember = (value: boolean) => {
      this.availability = { value, expiresAt: Date.now() + ttlMs };
      return value;
    };

    const docker = await this.getDocker();
    if (!docker) return remember(false);
    const timeoutMs = Number(process.env.SANDBOX_DOCKER_PING_TIMEOUT_MS) || 2000;
    let timer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        docker.ping(),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("docker ping timed out")), timeoutMs);
        }),
      ]);
      return remember(true);
    } catch {
      return remember(false);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * The underlying client, for callers that manage their own containers (the
   * Lab Manager). Returns null when the driver could not be loaded.
   */
  async getDockerClient(): Promise<DockerodeType | null> {
    return this.getDocker();
  }

  /** True when the image already exists on the Docker host. */
  async hasImage(image: string): Promise<boolean> {
    const docker = await this.getDocker();
    if (!docker) return false;
    try {
      await docker.getImage(image).inspect();
      return true;
    } catch {
      return false;
    }
  }

  async run(req: ToolRunRequest): Promise<ToolRunResult> {
    const timestamp = new Date().toISOString();
    const timeoutMs = req.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const image = req.image;
    if (!image) {
      throw new Error(`DockerExecutor requires an image for tool "${req.toolId}"`);
    }

    const docker = await this.getDocker();
    if (!docker) {
      throw new Error("dockerode is not available");
    }

    // Network: a dedicated internal bridge, or none at all for offline tools.
    // Never the host's shared default bridge.
    const needsNetwork = req.needsNetwork !== false;
    const mode = networkModeFor(needsNetwork);
    const network =
      mode === "none" ? "none" : await ensureSandboxNetwork(docker);
    const egressBlocked = mode === "none" || !allowEgress();

    const limits = req.resourceLimits ?? { cpus: 1, memoryMb: 512, pids: 256 };
    const workspace = "/tmp/cyberguard";

    const sandboxBase: Omit<SandboxInfo, "containerId"> = {
      isolated: true,
      cpuLimit: String(limits.cpus),
      memoryLimit: `${limits.memoryMb}MB`,
      network,
      egressBlocked,
      workspace,
      mode: "docker",
    };

    // Ensure the image exists locally, pulling once if needed.
    await ensureImagePresent(docker, image);

    let container: Container | null = null;
    try {
      container = await docker.createContainer({
        Image: image,
        Cmd: req.args,
        Tty: true,
        AttachStdout: true,
        AttachStderr: true,
        WorkingDir: workspace,
        HostConfig: {
          NetworkMode: network,
          ReadonlyRootfs: true,
          // The only writable path, and it dies with the container.
          Tmpfs: { [workspace]: "rw,noexec,nosuid,size=64m" },
          Memory: limits.memoryMb * 1024 * 1024,
          MemorySwap: limits.memoryMb * 1024 * 1024, // no swap headroom
          NanoCpus: Math.round(limits.cpus * 1_000_000_000),
          PidsLimit: limits.pids,
          CapDrop: ["ALL"],
          SecurityOpt: ["no-new-privileges"],
          // Never expose the host Docker socket or grant host namespaces.
          Privileged: false,
          IpcMode: "private",
          UsernsMode: "",
          // The one permitted bind: an already-containment-checked workspace
          // path, mounted read-only. Never the host Docker socket.
          Binds: req.workspaceHostPath
            ? [`${req.workspaceHostPath}:${CONTAINER_WORKSPACE}:ro`]
            : [],
          AutoRemove: false,
        },
      });

      await container.start();

      let timedOut = false;
      let timer: NodeJS.Timeout | undefined;
      const timeoutPromise = new Promise<{ StatusCode: number }>((resolve) => {
        timer = setTimeout(async () => {
          timedOut = true;
          try {
            await container!.kill();
          } catch {
            /* already gone */
          }
          resolve({ StatusCode: 124 });
        }, timeoutMs);
      });

      const result = await Promise.race([container.wait(), timeoutPromise]);
      if (timer) clearTimeout(timer);

      const logBuf = (await container.logs({
        stdout: true,
        stderr: true,
        follow: false,
      })) as unknown as Buffer;
      const rawOutput = logBuf.toString("utf8");

      const info = await container.inspect().catch(() => null);
      const containerId = info?.Id?.substring(0, 12) ?? "unknown";
      const exitCode = timedOut ? 124 : (result?.StatusCode ?? 0);
      const status: ToolRunResult["status"] = timedOut
        ? "TIMEOUT"
        : exitCode === 0
          ? "SUCCESS"
          : "FAILED";

      return {
        toolId: req.toolId,
        target: req.target,
        timestamp,
        status,
        exitCode,
        sandbox: { containerId, ...sandboxBase },
        rawOutput,
        structuredData: {
          simulated: false,
          targetHost: req.target,
          scannedAt: timestamp,
          tool: req.toolId,
          args: req.args,
          image,
          params: req.params ?? {},
          timeoutMs,
          networkMode: mode,
          egressBlocked,
          resourceLimits: limits,
        },
      };
    } finally {
      if (container) {
        try {
          await container.remove({ force: true });
        } catch {
          /* best-effort cleanup */
        }
      }
    }
  }
}
