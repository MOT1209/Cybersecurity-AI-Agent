/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lab Manager (§17). Runs intentionally-vulnerable applications as targets on
 * the sandbox's isolated network.
 *
 * These containers are deliberately insecure — that is their purpose — so the
 * isolation rules are stricter than for tool containers, not looser:
 *
 *   - a lab is attached ONLY to the internal sandbox network. No published host
 *     ports, ever. A vulnerable app reachable from the host's network is not a
 *     lab, it is an incident.
 *   - the catalog is a fixed allowlist of known images. A caller cannot name an
 *     arbitrary image to run, which would be remote code execution by API.
 *   - lab hostnames resolve inside the sandbox network, and the security
 *     gateway already treats `*.lab` and private addresses as in-scope, so
 *     agents can reach a lab without widening the project's real scope.
 *
 * Status is read from Docker, never assumed. A lab whose container is gone
 * reports STOPPED, not RUNNING.
 */

import type DockerodeType from "dockerode";
import { DockerExecutor } from "../sandbox/docker";
import { ensureSandboxNetwork, SANDBOX_NETWORK_NAME } from "../sandbox/network";
import { addAuditLog } from "../core/store";
import { emitEvent } from "../core/events";
import { ToolNotAvailableError } from "../core/errors";

export type LabStatus = "RUNNING" | "STOPPED" | "STARTING" | "UNKNOWN";

export interface LabDefinition {
  id: string;
  name: string;
  description: string;
  /** Pinned image. Only images in this catalog may ever be started. */
  image: string;
  /** Port the app listens on INSIDE the network. Never published to the host. */
  port: number;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  /** Hostname other containers use to reach it on the sandbox network. */
  hostname: string;
}

/**
 * The lab catalog. Fixed: a caller supplies an id from this list, never an
 * image reference.
 *
 * Tags are pinned to a release wherever the publisher offers one. DVWA is the
 * exception — upstream only publishes `latest` — so that entry is a moving
 * target by the publisher's choice, not by ours.
 */
export const LAB_CATALOG: readonly LabDefinition[] = Object.freeze([
  {
    id: "juice-shop",
    name: "OWASP Juice Shop",
    description: "Modern JavaScript web application carrying the full OWASP Top 10.",
    image: "bkimminich/juice-shop:v17.1.1",
    port: 3000,
    difficulty: "Intermediate",
    hostname: "juice-shop.lab",
  },
  {
    id: "dvwa",
    name: "Damn Vulnerable Web Application",
    description: "Classic PHP/MySQL teaching target with selectable difficulty.",
    image: "vulnerables/web-dvwa:latest",
    port: 80,
    difficulty: "Beginner",
    hostname: "dvwa.lab",
  },
  {
    id: "webgoat",
    name: "OWASP WebGoat",
    description: "Guided lessons covering common web vulnerability classes.",
    image: "webgoat/webgoat:v2023.8",
    port: 8080,
    difficulty: "Beginner",
    hostname: "webgoat.lab",
  },
]);

export function getLabDefinition(id: string): LabDefinition | undefined {
  return LAB_CATALOG.find((l) => l.id === id);
}

export interface LabState extends LabDefinition {
  status: LabStatus;
  containerId?: string;
  /** URL reachable from INSIDE the sandbox network only. */
  internalUrl: string;
  /** Why the lab is in this state. Always populated. */
  detail: string;
  startedAt?: string;
}

/** Container name for a lab, so state survives a process restart. */
function containerName(id: string): string {
  return `cyberguard_lab_${id}`;
}

/**
 * How the manager reaches Docker. Resolves to null when the daemon is not
 * usable — the caller then reports that fact rather than guessing a state.
 */
export type LabDockerProvider = () => Promise<DockerodeType | null>;

const executor = new DockerExecutor();

const realProvider: LabDockerProvider = async () => {
  const d = await executor.getDockerClient();
  if (!d || !(await executor.isAvailable())) return null;
  return d;
};

let dockerProvider: LabDockerProvider = realProvider;

/**
 * Test seam. The isolation rules above are the reason this module exists, so
 * they have to be assertable without a live daemon: a fake client lets a test
 * read back exactly what would be sent to Docker. Pass null to restore the
 * real provider.
 */
export function setLabDockerProvider(provider: LabDockerProvider | null): void {
  dockerProvider = provider ?? realProvider;
}

async function dockerOrThrow(): Promise<DockerodeType> {
  const d = await dockerProvider();
  if (!d) {
    throw new ToolNotAvailableError(
      "lab-manager",
      "the Docker daemon is unreachable, so no lab can be started or inspected",
    );
  }
  return d;
}

/** Inspect the real container state for one lab. Never guesses. */
export async function getLabState(id: string): Promise<LabState> {
  const def = getLabDefinition(id);
  if (!def) throw new Error(`Unknown lab "${id}". Labs must come from the fixed catalog.`);

  const base: LabState = {
    ...def,
    status: "UNKNOWN",
    internalUrl: `http://${def.hostname}:${def.port}`,
    detail: "",
  };

  let d: DockerodeType;
  try {
    d = await dockerOrThrow();
  } catch (err) {
    return { ...base, status: "STOPPED", detail: (err as Error).message };
  }

  try {
    const info = await d.getContainer(containerName(id)).inspect();
    const running = info.State?.Running === true;
    return {
      ...base,
      status: running ? "RUNNING" : "STOPPED",
      containerId: info.Id?.substring(0, 12),
      startedAt: info.State?.StartedAt,
      detail: running
        ? `Container is running on the ${SANDBOX_NETWORK_NAME} network.`
        : `Container exists but is not running (${info.State?.Status ?? "unknown"}).`,
    };
  } catch {
    return { ...base, status: "STOPPED", detail: "No container exists for this lab." };
  }
}

export async function listLabStates(): Promise<LabState[]> {
  return Promise.all(LAB_CATALOG.map((l) => getLabState(l.id)));
}

/**
 * Start a lab. Idempotent: an already-running lab is returned as-is.
 *
 * The container gets NO published ports, a memory/pid ceiling, and the internal
 * sandbox network. It is reachable by agents and by nothing else.
 */
export async function startLab(id: string, actor = "LabManager"): Promise<LabState> {
  const def = getLabDefinition(id);
  if (!def) throw new Error(`Unknown lab "${id}". Labs must come from the fixed catalog.`);

  const existing = await getLabState(id);
  if (existing.status === "RUNNING") return existing;

  const d = await dockerOrThrow();
  const network = await ensureSandboxNetwork(d);

  // Remove a stopped leftover so create() does not collide on the name.
  try {
    await d.getContainer(containerName(id)).remove({ force: true });
  } catch {
    /* nothing to remove */
  }

  try {
    await d.getImage(def.image).inspect();
  } catch {
    const stream: NodeJS.ReadableStream = await (d as unknown as {
      pull(image: string): Promise<NodeJS.ReadableStream>;
    }).pull(def.image);
    await new Promise<void>((resolve, reject) => {
      (d as unknown as { modem: { followProgress(s: NodeJS.ReadableStream, cb: (e: unknown) => void): void } })
        .modem.followProgress(stream, (err: unknown) => (err ? reject(err) : resolve()));
    });
  }

  const container = await d.createContainer({
    name: containerName(id),
    Image: def.image,
    Hostname: def.hostname.split(".")[0],
    Labels: { "cyberguard.lab": id, "cyberguard.managed": "true" },
    HostConfig: {
      NetworkMode: network,
      // No PortBindings. A deliberately vulnerable app must never be published
      // to the host — that is the whole point of running it in a lab.
      PublishAllPorts: false,
      Memory: 1024 * 1024 * 1024,
      PidsLimit: 512,
      SecurityOpt: ["no-new-privileges"],
      Privileged: false,
      Binds: [],
      RestartPolicy: { Name: "no" },
    },
    NetworkingConfig: {
      EndpointsConfig: {
        [network]: { Aliases: [def.hostname, def.hostname.split(".")[0]] },
      },
    },
  });

  await container.start();

  addAuditLog(
    actor,
    `LAB_START_${id.toUpperCase()}`,
    def.hostname,
    "STARTED",
    `Lab "${def.name}" started on the ${network} network with no published host ports.`,
  );
  emitEvent("TASK_STARTED", { target: def.hostname, detail: `lab ${id} started` });

  return getLabState(id);
}

/** Stop and remove a lab container. Idempotent. */
export async function stopLab(id: string, actor = "LabManager"): Promise<LabState> {
  const def = getLabDefinition(id);
  if (!def) throw new Error(`Unknown lab "${id}".`);

  const d = await dockerOrThrow();
  try {
    const c = d.getContainer(containerName(id));
    await c.stop({ t: 5 }).catch(() => {});
    await c.remove({ force: true });
    addAuditLog(actor, `LAB_STOP_${id.toUpperCase()}`, def.hostname, "STOPPED", `Lab "${def.name}" stopped and removed.`);
  } catch {
    /* already gone */
  }
  return getLabState(id);
}
