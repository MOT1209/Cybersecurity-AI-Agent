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
 * reports STOPPED, not RUNNING. And when Docker cannot be reached at all the
 * answer is UNKNOWN — "I could not tell" is a different fact from "it is
 * stopped", and collapsing the two makes the platform assert what it does not
 * know.
 *
 * Two facts are kept separate throughout, because conflating them produced a
 * false negative (§2.7): the container state (`containerRunning`), read from
 * `docker inspect`, and the service verdict (`status`), which is `RUNNING` only
 * when a probe observed the app answering. A container that is up while the app
 * is still booting is `STARTING` — for DVWA that gap is ~21s.
 */

import type DockerodeType from "dockerode";
import { DockerExecutor } from "../sandbox/docker";
import { ensureSandboxNetwork, SANDBOX_NETWORK_NAME } from "../sandbox/network";
import { addAuditLog } from "../core/store";
import { emitEvent } from "../core/events";
import { ToolNotAvailableError } from "../core/errors";
import {
  ensureProbeImage,
  labProbeImage,
  observeLabReadiness,
  probeContainerName,
} from "./readiness";
import type { LabReadiness } from "./readiness";

/**
 * The *service* verdict, derived from the two observations in {@link LabState}:
 *
 *   RUNNING   a probe observed the app answering — not merely a live container
 *   STARTING  the container is up, but the app has not answered yet
 *   STOPPED   no container is running (absence was observed)
 *   UNKNOWN   the verdict could not be determined — daemon unreachable, or a
 *             running container whose readiness could not be observed. Never
 *             rounded to STOPPED (invents a stopped container) or to RUNNING
 *             (invents a serving app).
 */
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
  /** Service verdict. `RUNNING` requires an observed answer, never a guess. */
  status: LabStatus;
  /**
   * Container-level fact, read from `docker inspect`. `null` means it could not
   * be read — which is not the same as `false`. Kept separate from `status` so
   * "the container is up" and "the lab is ready" cannot be mistaken for each
   * other.
   */
  containerRunning: boolean | null;
  containerId?: string;
  /** URL reachable from INSIDE the sandbox network only. */
  internalUrl: string;
  /** The observation behind `status`. Always populated, like `detail`. */
  readiness: LabReadiness;
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

/** Human-readable "how long has it been up", or "" when Docker gave no time. */
function upFor(startedAt?: string): string {
  const ms = startedAt ? Date.now() - Date.parse(startedAt) : NaN;
  if (!Number.isFinite(ms) || ms < 0) return "";
  return ` (up ${Math.round(ms / 1000)}s)`;
}

/**
 * Read the container state, then observe readiness if — and only if — there is a
 * running container to ask. Never guesses, and never lets "cannot tell" round to
 * either "running" or "stopped".
 */
export async function getLabState(id: string): Promise<LabState> {
  const def = getLabDefinition(id);
  if (!def) throw new Error(`Unknown lab "${id}". Labs must come from the fixed catalog.`);

  const base: LabState = {
    ...def,
    status: "UNKNOWN",
    containerRunning: null,
    internalUrl: `http://${def.hostname}:${def.port}`,
    readiness: {
      state: "UNVERIFIED",
      probeImage: labProbeImage(),
      evidence: "Docker was not consulted, so nothing was observed.",
    },
    detail: "",
  };

  let d: DockerodeType;
  try {
    d = await dockerOrThrow();
  } catch (err) {
    // No daemon means no observation. Reporting STOPPED here would be the
    // platform inventing a container state it never read.
    const reason = (err as Error).message;
    return {
      ...base,
      status: "UNKNOWN",
      readiness: { state: "UNVERIFIED", probeImage: labProbeImage(), evidence: reason },
      detail: `The container state could not be read: ${reason}`,
    };
  }

  const inspected = await d
    .getContainer(containerName(id))
    .inspect()
    .then(
      (info) => ({ ok: true as const, info }),
      () => ({ ok: false as const, info: null }),
    );

  if (!inspected.ok) {
    // Inspect is the only Docker read made here, so a failure really does mean
    // there is no container. Nothing is running, therefore nothing is serving.
    return {
      ...base,
      status: "STOPPED",
      containerRunning: false,
      readiness: {
        state: "NOT_READY",
        probeImage: labProbeImage(),
        evidence: "no container exists for this lab, so there is nothing to probe",
      },
      detail: "No container exists for this lab.",
    };
  }

  const info = inspected.info;
  const containerId = info.Id?.substring(0, 12);
  const startedAt = info.State?.StartedAt;
  const running = info.State?.Running === true;

  if (!running) {
    const status = info.State?.Status ?? "unknown";
    return {
      ...base,
      status: "STOPPED",
      containerRunning: false,
      containerId,
      startedAt,
      readiness: {
        state: "NOT_READY",
        probeImage: labProbeImage(),
        evidence: `the container exists but is not running (${status}), so nothing is serving`,
      },
      detail: `Container exists but is not running (${status}).`,
    };
  }

  // The container is up. That is a container fact, and on its own it is not
  // evidence that the app is serving — so ask the app.
  const readiness = await observeLabReadiness(d, { id, url: base.internalUrl });
  const observed = {
    ...base,
    containerRunning: true,
    containerId,
    startedAt,
    readiness,
  };

  if (readiness.state === "READY") {
    return {
      ...observed,
      status: "RUNNING",
      detail: `Container is running on the ${SANDBOX_NETWORK_NAME} network and ${readiness.evidence}.`,
    };
  }

  if (readiness.state === "NOT_READY") {
    return {
      ...observed,
      status: "STARTING",
      detail: `Container is running${upFor(startedAt)} but the app is not answering yet — ${readiness.evidence}.`,
    };
  }

  return {
    ...observed,
    status: "UNKNOWN",
    detail:
      `Container is running${upFor(startedAt)}, but whether the app is serving could not be ` +
      `observed — ${readiness.evidence}.`,
  };
}

export async function listLabStates(): Promise<LabState[]> {
  return Promise.all(LAB_CATALOG.map((l) => getLabState(l.id)));
}

/**
 * Start a lab. Idempotent: a lab whose container is already up is returned as-is.
 *
 * The idempotency check is on the *container*, not on `status`. A lab whose
 * container is up but whose app has not answered yet reads `STARTING`; treating
 * that as "not started" would destroy a lab mid-boot and restart its clock.
 *
 * The container gets NO published ports, a memory/pid ceiling, and the internal
 * sandbox network. It is reachable by agents and by nothing else.
 */
export async function startLab(id: string, actor = "LabManager"): Promise<LabState> {
  const def = getLabDefinition(id);
  if (!def) throw new Error(`Unknown lab "${id}". Labs must come from the fixed catalog.`);

  const existing = await getLabState(id);
  if (existing.containerRunning === true) return existing;

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

  // Availability of the probe image is a precondition for ever reporting
  // RUNNING, so put it in place while the lab boots. A failure here is not
  // swallowed silently: the state below reports readiness as unverified, with
  // the reason, rather than assuming the app is fine.
  await ensureProbeImage(d);

  addAuditLog(
    actor,
    `LAB_START_${id.toUpperCase()}`,
    def.hostname,
    "STARTED",
    `Lab "${def.name}" started on the ${network} network with no published host ports. ` +
      "Readiness is now observed separately: RUNNING is reported only once the app answers.",
  );
  emitEvent("TASK_STARTED", { target: def.hostname, detail: `lab ${id} started` });

  return getLabState(id);
}

/** Stop and remove a lab container. Idempotent. */
export async function stopLab(id: string, actor = "LabManager"): Promise<LabState> {
  const def = getLabDefinition(id);
  if (!def) throw new Error(`Unknown lab "${id}".`);

  const d = await dockerOrThrow();
  // A probe is short-lived, but a hard crash can leave one behind; a stop should
  // leave nothing of this lab running.
  try {
    await d.getContainer(probeContainerName(id)).remove({ force: true });
  } catch {
    /* no probe left over */
  }
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
