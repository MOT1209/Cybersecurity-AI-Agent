/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lab readiness probe (§2.7). "The container is running" and "the lab is ready"
 * are two different facts, and this module exists because the platform used to
 * report only the first one under a name that read as the second.
 *
 * Measured on this machine before the split: Docker reported DVWA's container
 * running at +12s and Apache only answered later. For that whole window the API
 * said RUNNING about a target that could not be reached, so an agent that
 * started a lab and immediately scanned it recorded a false negative.
 *
 * Readiness is therefore never inferred from a container state. It is observed,
 * by making the same kind of HTTP request an agent would make, from a
 * short-lived container attached to the sandbox network. That container:
 *
 *   - is on the same internal network as the lab and nothing else,
 *   - publishes no port, drops all capabilities, has a read-only root
 *     filesystem and a memory/pid ceiling — a probe is not privileged,
 *   - is bounded twice: the HTTP request itself, and a wall-clock kill if the
 *     daemon or the container wedges.
 *
 * The request follows redirects and fails on HTTP error statuses, because a lab
 * whose root emits a `302` while its own database is still starting is not a
 * usable target. What counts as ready is therefore "served a non-error page at
 * its root", not "accepted a socket".
 *
 * A probe that cannot run at all returns UNVERIFIED, never "not ready": not
 * being able to tell is its own answer and must not be rounded to either side.
 */

import type DockerodeType from "dockerode";
import type { Container } from "dockerode";
import { SANDBOX_NETWORK_NAME } from "../sandbox/network";
import { ensureImagePresent } from "../sandbox/docker";

/**
 * Image the probe runs in. Pinned by tag: an unpinned probe image would be a
 * moving target deciding, silently, whether labs count as ready.
 */
export function labProbeImage(): string {
  return process.env.LAB_PROBE_IMAGE || "curlimages/curl:8.11.1";
}

/** Hard limit on the HTTP request the probe makes. */
const PROBE_HTTP_TIMEOUT_SECONDS = 5;

/** Marker around `%{http_code}` so the status can be read back unambiguously. */
const HTTP_CODE_MARKER = "HTTP_CODE=";

function probeTimeoutMs(): number {
  return Number(process.env.LAB_PROBE_TIMEOUT_MS) || 10_000;
}

export type ReadinessState = "READY" | "NOT_READY" | "UNVERIFIED";

export interface LabReadiness {
  /**
   * READY        a request from inside the sandbox network was served without
   *              an error status
   * NOT_READY    a request was made and that is not what happened — nothing
   *              answered yet, or an error status was returned, or nothing is
   *              running to ask. The `evidence` says which.
   * UNVERIFIED   no observation was possible — the probe could not run, or the
   *              image it needs is unavailable. Never treat this as either of
   *              the other two.
   */
  state: ReadinessState;
  /** When the probe actually ran. Absent when no probe could run. */
  observedAt?: string;
  /** What was observed, verbatim. Always populated. */
  evidence: string;
  /** HTTP status the lab answered with, when it answered at all. */
  httpStatus?: number;
  /** Image the observation requires, so a missing one can be named and pulled. */
  probeImage: string;
}

/** Container name for a probe, so a leftover from a crash can be cleared. */
export function probeContainerName(id: string): string {
  return `cyberguard_lab_probe_${id}`;
}

export interface ReadinessProbeRequest {
  /** Lab id — used only to name the probe container. */
  id: string;
  /** URL reachable from inside the sandbox network, e.g. http://dvwa.lab:80 */
  url: string;
}

/**
 * The request the probe makes: follow redirects (a lab's root commonly
 * redirects to a login page), fail on an HTTP error status (so a half-started
 * stack is not called ready), and print the final status behind a marker.
 */
export function probeArgs(url: string): string[] {
  return [
    "-s",
    "-S",
    "-o",
    "/dev/null",
    "-L",
    "--max-redirs",
    "3",
    "--max-time",
    String(PROBE_HTTP_TIMEOUT_SECONDS),
    "-f",
    "-w",
    `${HTTP_CODE_MARKER}%{http_code}`,
    url,
  ];
}

/** Curl exit codes worth naming, so the evidence says which failure it was. */
const CURL_EXIT_MEANING: Record<number, string> = {
  6: "the lab hostname did not resolve on the sandbox network",
  7: "nothing accepted a connection on the lab's port",
  22: "the app answered with an HTTP error status",
  28: "no HTTP response within the request timeout",
};

function trim(s: string, max = 240): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > max ? `${one.slice(0, max)}…` : one;
}

/**
 * The HTTP status curl reported, whichever way the transfer ended. curl writes
 * `000` when it got no response at all, which is the absence of a status rather
 * than a status of zero — reporting it as a number would be a small lie in a
 * field an operator reads.
 */
function httpStatusOf(raw: string): number | undefined {
  const parsed = Number(new RegExp(`${HTTP_CODE_MARKER}(\\d{3})`).exec(raw)?.[1]);
  return Number.isFinite(parsed) && parsed >= 100 ? parsed : undefined;
}

/**
 * Read whatever dockerode handed back as the container's logs.
 *
 * `logs()` does not reliably resolve to a Buffer: observed on this machine in
 * the same process, a non-numeric body came back as a Buffer while a body that
 * looks like a number (`%{http_code}` output, e.g. `302`) came back as a
 * Number. Calling `.toString("utf8")` on that threw
 * `RangeError: toString() radix argument must be between 2 and 36`, which the
 * probe reported as "could not run" — an honest but useless answer. So every
 * shape is handled explicitly instead of assuming one.
 */
export async function normalizeProbeOutput(raw: unknown): Promise<string> {
  if (raw === null || raw === undefined) return "";
  if (Buffer.isBuffer(raw)) return raw.toString("utf8");
  if (typeof raw === "string") return raw;
  if (typeof raw === "number" || typeof raw === "boolean") return String(raw);
  if (typeof (raw as NodeJS.ReadableStream).on === "function") {
    const stream = raw as NodeJS.ReadableStream;
    return new Promise<string>((resolve) => {
      const chunks: Buffer[] = [];
      const done = () => resolve(Buffer.concat(chunks).toString("utf8"));
      stream.on("data", (c: Buffer | string) => chunks.push(Buffer.from(c)));
      stream.on("end", done);
      stream.on("error", done);
      stream.on("close", done);
    });
  }
  return String(raw);
}

async function runProbe(
  docker: DockerodeType,
  req: ReadinessProbeRequest,
): Promise<LabReadiness> {
  const image = labProbeImage();
  const name = probeContainerName(req.id);
  const observedAt = new Date().toISOString();

  // Never pull from here. A status read must not cause a network side effect;
  // startLab pulls the probe image, and if it is still missing we say so rather
  // than reporting readiness we did not observe.
  try {
    await docker.getImage(image).inspect();
  } catch {
    return {
      state: "UNVERIFIED",
      probeImage: image,
      evidence:
        `the probe image "${image}" is not present locally, so readiness could not be ` +
        `observed (pull it with: docker pull ${image})`,
    };
  }

  // A hard crash can leave a probe behind; the name is fixed, so clear it first.
  try {
    await docker.getContainer(name).remove({ force: true });
  } catch {
    /* nothing to clear */
  }

  const timeoutMs = probeTimeoutMs();
  const startedAtMs = Date.now();
  let container: Container | null = null;
  try {
    container = await docker.createContainer({
      name,
      Image: image,
      Cmd: probeArgs(req.url),
      Tty: true,
      AttachStdout: true,
      AttachStderr: true,
      Labels: { "cyberguard.managed": "true", "cyberguard.lab-probe": req.id },
      HostConfig: {
        NetworkMode: SANDBOX_NETWORK_NAME,
        // A probe has no reason to be reachable from anywhere.
        PublishAllPorts: false,
        ReadonlyRootfs: true,
        Tmpfs: { "/tmp": "rw,noexec,nosuid,size=8m" },
        Memory: 64 * 1024 * 1024,
        MemorySwap: 64 * 1024 * 1024, // no swap headroom
        NanoCpus: 250_000_000,
        PidsLimit: 64,
        CapDrop: ["ALL"],
        SecurityOpt: ["no-new-privileges"],
        Privileged: false,
        IpcMode: "private",
        Binds: [],
        RestartPolicy: { Name: "no" },
        AutoRemove: false,
      },
    });

    await container.start();

    let killed = false;
    let timer: NodeJS.Timeout | undefined;
    const result = await Promise.race([
      container.wait(),
      new Promise<{ StatusCode: number }>((resolve) => {
        timer = setTimeout(async () => {
          killed = true;
          try {
            await container!.kill();
          } catch {
            /* already gone */
          }
          resolve({ StatusCode: 124 });
        }, timeoutMs);
      }),
    ]);
    if (timer) clearTimeout(timer);

    const raw = trim(await normalizeProbeOutput(await container.logs({
      stdout: true,
      stderr: true,
      follow: false,
    })).catch(() => ""));
    const exitCode = killed ? 124 : (result?.StatusCode ?? 0);
    const elapsedSeconds = Math.round((Date.now() - startedAtMs) / 1000);
    const httpStatus = httpStatusOf(raw);

    if (exitCode === 0) {
      return {
        state: "READY",
        observedAt,
        httpStatus,
        evidence:
          `a request from inside the sandbox network was served` +
          (httpStatus ? ` (HTTP ${httpStatus}, redirects followed)` : ""),
        probeImage: image,
      };
    }

    if (killed) {
      return {
        state: "NOT_READY",
        observedAt,
        httpStatus,
        evidence:
          `the probe was killed after ${elapsedSeconds}s without finishing` +
          (raw ? `: ${raw}` : ""),
        probeImage: image,
      };
    }

    const meaning = CURL_EXIT_MEANING[exitCode];
    return {
      state: "NOT_READY",
      observedAt,
      httpStatus,
      evidence:
        `the probe could not use the lab (curl exit ${exitCode}` +
        (meaning ? `, ${meaning}` : "") +
        (httpStatus ? `, final status HTTP ${httpStatus}` : "") +
        `)` +
        (raw ? `: ${raw}` : ""),
      probeImage: image,
    };
  } catch (err) {
    // The probe itself failed — that is ignorance, not a negative result.
    // Unlike "the app did not answer", this is an infrastructure fault, so it
    // also goes to the server log with its stack: the API response can only
    // carry the message, and a message alone is not diagnosable.
    console.error(`[labs] readiness probe for "${req.id}" failed:`, err);
    return {
      state: "UNVERIFIED",
      observedAt,
      evidence: `the readiness probe could not run: ${trim((err as Error).message)}`,
      probeImage: image,
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

/** In-flight probes by lab id, so concurrent reads cannot race on the name. */
const inFlight = new Map<string, Promise<LabReadiness>>();

/**
 * Observe whether the lab is serving right now.
 *
 * Always a fresh observation: readiness is time-sensitive, so a cached "ready"
 * would be exactly the kind of stale claim this platform exists to remove. The
 * cost is one short-lived container per inspection of a *running* lab; stopped
 * labs cost nothing, because there is nothing to ask. Concurrent calls for the
 * same lab share one probe rather than colliding on the container name.
 */
export function observeLabReadiness(
  docker: DockerodeType,
  req: ReadinessProbeRequest,
): Promise<LabReadiness> {
  const running = inFlight.get(req.id);
  if (running) return running;
  const probe = runProbe(docker, req).finally(() => inFlight.delete(req.id));
  inFlight.set(req.id, probe);
  return probe;
}

/**
 * Make the probe image available so readiness can be observed at all. Called by
 * `startLab` (a write action, where a pull is a reasonable side effect), never
 * from a status read. Failure is deliberately swallowed: the reason surfaces in
 * the readiness evidence of the very next inspection, which is where an
 * operator looks for it.
 */
export async function ensureProbeImage(docker: DockerodeType): Promise<void> {
  try {
    await ensureImagePresent(docker, labProbeImage());
  } catch {
    /* reported through the readiness observation */
  }
}
