import { describe, it, expect, beforeAll, afterEach } from "vitest";
import request from "supertest";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
  delete process.env.APP_ACCESS_KEY;
  delete process.env.API_PRINCIPALS;
});

import {
  LAB_CATALOG,
  getLabDefinition,
  getLabState,
  listLabStates,
  startLab,
  stopLab,
  setLabDockerProvider,
} from "../src/server/labs/manager";
import { Readable } from "node:stream";
import type { LabState } from "../src/server/labs/manager";
import { SANDBOX_NETWORK_NAME } from "../src/server/sandbox/network";
import { labProbeImage, normalizeProbeOutput, probeArgs } from "../src/server/labs/readiness";
import { resetPrincipals } from "../src/server/security/principal";
import { createApp } from "../server";

/**
 * Starting/stopping a lab requires the operator role. These HTTP tests
 * authenticate as one; reads stay anonymous (viewer), which is exactly the
 * open-dev contract. The afterEach below restores open-dev so the honest
 * UNKNOWN-when-unreachable assertions keep testing the unauthenticated path.
 */
const OPERATOR_KEY = "lab-operator-secret";
function asOperator() {
  process.env.API_PRINCIPALS = `lab-operator:operator:${OPERATOR_KEY}`;
  resetPrincipals();
}

/**
 * A fake Docker client, in the same spirit as the fake `PgPool` in
 * `database.test.ts`: it records exactly what the manager asked Docker to do,
 * so the isolation properties can be asserted without a daemon.
 *
 * The Lab Manager exists to run deliberately vulnerable applications where
 * nothing outside the sandbox network can reach them. That claim is only worth
 * something if a test reads back the real container-create options.
 */
function fakeDocker(
  opts: {
    existing?: Record<string, { running: boolean; status?: string }>;
    hasImage?: boolean;
    /** Is the probe image present locally? Default yes. */
    probeImage?: boolean;
    /** Does the app answer the probe? Default yes. A test may flip it later. */
    answering?: boolean;
    /** When set, the app answers with this HTTP error status (curl exit 22). */
    errorStatus?: number;
    /** Does pulling the probe image fail (offline / private registry)? */
    probePullFails?: boolean;
  } = {},
) {
  const containers: Record<string, { running: boolean; status?: string }> = {
    ...(opts.existing ?? {}),
  };
  /** Mutable, so a test can model an app that comes up mid-run. */
  const state = {
    answering: opts.answering ?? true,
    errorStatus: opts.errorStatus,
    probePresent: opts.probeImage ?? true,
    probePullFails: opts.probePullFails ?? false,
    labImagePresent: opts.hasImage ?? true,
    /** When set, a probe blocks here until it resolves. Lets a test hold a
     * probe open and observe what concurrent callers do; no timers involved. */
    probeHold: undefined as Promise<void> | undefined,
  };
  const calls = {
    // Lab containers only. Probe containers are recorded separately, so an
    // assertion like "exactly one container was created" keeps meaning that.
    created: [] as any[],
    probes: [] as any[],
    started: [] as string[],
    stopped: [] as string[],
    removed: [] as string[],
    probesRemoved: [] as string[],
    pulled: [] as string[],
    probePulled: [] as string[],
    networksCreated: [] as string[],
  };

  const docker: any = {
    getContainer(name: string) {
      return {
        async inspect() {
          const c = containers[name];
          if (!c) throw new Error(`no such container: ${name}`);
          return {
            Id: "deadbeefcafe0000",
            State: {
              Running: c.running,
              Status: c.status ?? (c.running ? "running" : "exited"),
              StartedAt: "2026-01-01T00:00:00Z",
            },
          };
        },
        async stop() {
          if (!containers[name]) throw new Error("no such container");
          calls.stopped.push(name);
          containers[name].running = false;
        },
        async remove() {
          if (!containers[name]) throw new Error("no such container");
          calls.removed.push(name);
          delete containers[name];
        },
      };
    },
    getImage(image: string) {
      return {
        async inspect() {
          // Presence is tracked per image: the probe image and the lab images
          // are different pulls with different failure modes.
          const present =
            image === labProbeImage() ? state.probePresent : state.labImagePresent;
          if (!present) throw new Error(`no such image: ${image}`);
          return { Id: "sha256:fake" };
        },
      };
    },
    async pull(image: string) {
      if (image === labProbeImage()) {
        calls.probePulled.push(image);
        if (state.probePullFails) throw new Error("pull access denied for probe image");
        state.probePresent = true;
        return {} as NodeJS.ReadableStream;
      }
      calls.pulled.push(image);
      state.labImagePresent = true;
      return {} as NodeJS.ReadableStream;
    },
    modem: {
      followProgress(_stream: unknown, cb: (e: unknown) => void) {
        cb(null);
      },
    },
    getNetwork(name: string) {
      return {
        async inspect() {
          return { Name: name };
        },
      };
    },
    async createNetwork(cfg: any) {
      calls.networksCreated.push(cfg.Name);
      return {};
    },
    async createContainer(cfg: any) {
      const isProbe = cfg?.Labels?.["cyberguard.lab-probe"] !== undefined;
      containers[cfg.name] = { running: false };

      if (isProbe) {
        calls.probes.push(cfg);
        return {
          async start() {
            containers[cfg.name] = { running: true };
          },
          async wait() {
            if (state.probeHold) await state.probeHold;
            if (!state.answering) return { StatusCode: 7 };
            if (state.errorStatus) return { StatusCode: 22 };
            return { StatusCode: 0 };
          },
          async logs() {
            if (!state.answering) {
              return Buffer.from(
                "curl: (7) Failed to connect to the lab port: Connection refused HTTP_CODE=000",
              );
            }
            if (state.errorStatus) {
              return Buffer.from(
                `curl: (22) The requested URL returned error: ${state.errorStatus} HTTP_CODE=${state.errorStatus}`,
              );
            }
            return Buffer.from("HTTP_CODE=200");
          },
          async inspect() {
            return { Id: "probe0000000" };
          },
          async kill() {
            containers[cfg.name] = { running: false };
          },
          async remove() {
            calls.probesRemoved.push(cfg.name);
            delete containers[cfg.name];
          },
        };
      }

      calls.created.push(cfg);
      return {
        async start() {
          calls.started.push(cfg.name);
          containers[cfg.name] = { running: true };
        },
        async wait() {
          return { StatusCode: 0 };
        },
        async logs() {
          return Buffer.from("");
        },
        async inspect() {
          return { Id: "deadbeefcafe0000" };
        },
        async kill() {
          /* nothing */
        },
        async remove() {
          calls.removed.push(cfg.name);
          delete containers[cfg.name];
        },
      };
    },
  };

  return { docker, calls, containers, state };
}

afterEach(() => {
  setLabDockerProvider(null);
  delete process.env.API_PRINCIPALS;
  resetPrincipals();
});

describe("lab catalog", () => {
  it("only ever offers ids from a fixed allowlist", () => {
    expect(LAB_CATALOG.length).toBeGreaterThan(0);
    expect(Object.isFrozen(LAB_CATALOG)).toBe(true);
    expect(getLabDefinition("juice-shop")).toBeDefined();
    expect(getLabDefinition("../../etc/passwd")).toBeUndefined();
    expect(getLabDefinition("alpine")).toBeUndefined();
  });

  it("names an explicit tag or digest for every image", () => {
    for (const lab of LAB_CATALOG) {
      const pinned = lab.image.includes("@sha256:") || /:[\w][\w.-]*$/.test(lab.image);
      expect(pinned, `${lab.id} must declare a tag or digest`).toBe(true);
      expect(lab.hostname.endsWith(".lab")).toBe(true);
      expect(lab.port).toBeGreaterThan(0);
    }
  });
});

describe("starting a lab", () => {
  it("never publishes a port to the host", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    await startLab("juice-shop");

    expect(fake.calls.created).toHaveLength(1);
    const cfg = fake.calls.created[0];
    // The entire isolation claim lives in these three assertions.
    expect(cfg.HostConfig.PortBindings).toBeUndefined();
    expect(cfg.HostConfig.PublishAllPorts).toBe(false);
    expect(cfg.ExposedPorts).toBeUndefined();
  });

  it("attaches the container to the internal sandbox network only", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    await startLab("dvwa");

    const cfg = fake.calls.created[0];
    expect(cfg.HostConfig.NetworkMode).toBe(SANDBOX_NETWORK_NAME);
    expect(Object.keys(cfg.NetworkingConfig.EndpointsConfig)).toEqual([SANDBOX_NETWORK_NAME]);
    expect(cfg.NetworkingConfig.EndpointsConfig[SANDBOX_NETWORK_NAME].Aliases).toContain("dvwa.lab");
  });

  it("starts only a catalog image, and only the one the id names", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    await startLab("webgoat");

    expect(fake.calls.created[0].Image).toBe(getLabDefinition("webgoat")!.image);
    expect(LAB_CATALOG.map((l) => l.image)).toContain(fake.calls.created[0].Image);
  });

  it("refuses an id outside the catalog before touching Docker", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    await expect(startLab("bkimminich/juice-shop")).rejects.toThrow(/fixed catalog/);
    await expect(startLab("evil-image:latest")).rejects.toThrow(/Unknown lab/);
    expect(fake.calls.created).toHaveLength(0);
    expect(fake.calls.pulled).toHaveLength(0);
  });

  it("keeps the container unprivileged and free of bind mounts", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    await startLab("juice-shop");

    const hc = fake.calls.created[0].HostConfig;
    expect(hc.Privileged).toBe(false);
    expect(hc.SecurityOpt).toContain("no-new-privileges");
    expect(hc.Binds).toEqual([]);
    expect(hc.Memory).toBeGreaterThan(0);
    expect(hc.PidsLimit).toBeGreaterThan(0);
  });

  it("is idempotent: an already-running lab is returned, not started again", async () => {
    const fake = fakeDocker({ existing: { "cyberguard_lab_juice-shop": { running: true } } });
    setLabDockerProvider(async () => fake.docker);

    const state = await startLab("juice-shop");

    expect(state.status).toBe("RUNNING");
    expect(fake.calls.created).toHaveLength(0);
    expect(fake.calls.started).toHaveLength(0);
    expect(fake.calls.removed).toHaveLength(0);
  });

  it("clears a stopped leftover so the container name cannot collide", async () => {
    const fake = fakeDocker({
      existing: { "cyberguard_lab_dvwa": { running: false, status: "exited" } },
    });
    setLabDockerProvider(async () => fake.docker);

    const state = await startLab("dvwa");

    expect(fake.calls.removed).toContain("cyberguard_lab_dvwa");
    expect(fake.calls.created).toHaveLength(1);
    expect(state.status).toBe("RUNNING");
  });

  it("pulls the image only when it is missing", async () => {
    const present = fakeDocker({ hasImage: true });
    setLabDockerProvider(async () => present.docker);
    await startLab("juice-shop");
    expect(present.calls.pulled).toHaveLength(0);

    const missing = fakeDocker({ hasImage: false });
    setLabDockerProvider(async () => missing.docker);
    await startLab("juice-shop");
    expect(missing.calls.pulled).toEqual([getLabDefinition("juice-shop")!.image]);
  });
});

describe("lab status is read from Docker, never assumed", () => {
  it("stops reporting RUNNING once the container is gone", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    expect((await startLab("juice-shop")).status).toBe("RUNNING");

    // Something outside the platform removes the container.
    delete fake.containers["cyberguard_lab_juice-shop"];

    const after = await getLabState("juice-shop");
    expect(after.status).toBe("STOPPED");
    expect(after.containerRunning).toBe(false);
    expect(after.detail).toMatch(/No container exists/);
  });

  it("reports STOPPED with the reason when a container exists but is not running", async () => {
    const fake = fakeDocker({
      existing: { "cyberguard_lab_webgoat": { running: false, status: "exited" } },
    });
    setLabDockerProvider(async () => fake.docker);

    const state = await getLabState("webgoat");
    expect(state.status).toBe("STOPPED");
    expect(state.detail).toMatch(/exited/);
  });

  it("says UNKNOWN when the daemon is unreachable, rather than inventing a status", async () => {
    setLabDockerProvider(async () => null);

    const state = await getLabState("juice-shop");

    // "I could not read the container" is not "the container is stopped".
    // Reporting STOPPED here would assert a state nothing ever observed.
    expect(state.status).toBe("UNKNOWN");
    expect(state.status).not.toBe("STOPPED");
    expect(state.detail).toMatch(/Docker daemon is unreachable/);
    expect(state.containerId).toBeUndefined();
    expect(state.startedAt).toBeUndefined();
    // The container fact is `null` — unread — not `false`.
    expect(state.containerRunning).toBeNull();
    expect(state.readiness.state).toBe("UNVERIFIED");

    // Acting on that ignorance is refused outright, with a reason.
    await expect(startLab("juice-shop")).rejects.toThrow(/NOT_AVAILABLE/);
  });

  it("offers an internal URL only — never a host address", async () => {
    setLabDockerProvider(async () => null);

    for (const state of await listLabStates()) {
      expect(state.internalUrl).toBe(`http://${state.hostname}:${state.port}`);
      expect(state.internalUrl).not.toMatch(/localhost|127\.0\.0\.1|0\.0\.0\.0/);
      expect(state.detail).not.toBe("");
      // An unreadable daemon must not read as "nothing is running here".
      expect(state.status).toBe("UNKNOWN");
    }
  });

  it("rejects an unknown id", async () => {
    setLabDockerProvider(async () => null);
    await expect(getLabState("nope")).rejects.toThrow(/Unknown lab/);
  });
});

describe("reading the probe's own output", () => {
  it("handles every shape dockerode has handed back, not just a Buffer", async () => {
    // Running this for real caught the assumption: `container.logs()` resolved
    // to a Buffer for a non-numeric body and to a Number for a numeric one, so
    // `.toString("utf8")` threw "radix argument must be between 2 and 36" and
    // the probe reported that it could not run at all.
    expect(await normalizeProbeOutput(Buffer.from("HTTP_CODE=200"))).toBe("HTTP_CODE=200");
    expect(await normalizeProbeOutput("HTTP_CODE=200")).toBe("HTTP_CODE=200");
    expect(await normalizeProbeOutput(302)).toBe("302");
    expect(await normalizeProbeOutput(0)).toBe("0");
    expect(await normalizeProbeOutput(null)).toBe("");
    expect(await normalizeProbeOutput(undefined)).toBe("");
    expect(
      await normalizeProbeOutput(Readable.from([Buffer.from("HTTP_CODE=201")])),
    ).toBe("HTTP_CODE=201");
  });

  it("asks for a non-error page at the lab root, following redirects", () => {
    const args = probeArgs("http://dvwa.lab:80");
    expect(args).toContain("-L");
    expect(args).toContain("-f");
    expect(args.join(" ")).toContain("--max-time");
    expect(args.at(-1)).toBe("http://dvwa.lab:80");
  });

  it("does not turn curl's \"no response\" into a status", async () => {
    // "HTTP_CODE=000" is what curl prints when nothing answered. A consumer of
    // this API reads `httpStatus`, so 000 must not arrive there as 0.
    const fake = fakeDocker({ answering: false });
    setLabDockerProvider(async () => fake.docker);

    const state = await startLab("webgoat");
    expect(state.readiness.httpStatus).toBeUndefined();
  });
});

describe("a running container is not a ready lab (§2.7)", () => {
  it("reports STARTING — never RUNNING — while the container is up but the app has not answered", async () => {
    const fake = fakeDocker({ answering: false });
    setLabDockerProvider(async () => fake.docker);

    // The defect this replaces: the container came up ~21s before DVWA's Apache
    // answered, and the API called that RUNNING.
    const state = await startLab("dvwa");

    expect(state.containerRunning).toBe(true);
    expect(state.status).toBe("STARTING");
    expect(state.status).not.toBe("RUNNING");
    expect(state.readiness.state).toBe("NOT_READY");
    expect(state.readiness.observedAt).toBeTruthy();
    // curl writes 000 when it got no response: not a status of zero.
    expect(state.readiness.httpStatus).toBeUndefined();
    expect(state.detail).toMatch(/not answering yet/);
    expect(state.detail).toMatch(/curl exit 7/);
  });

  it("reports NOT_READY when the app answers with an error status", async () => {
    // A half-started stack can serve a redirect to a page that then fails: the
    // app answered, and the lab is still not a usable target.
    const fake = fakeDocker({ errorStatus: 500 });
    setLabDockerProvider(async () => fake.docker);

    const state = await startLab("juice-shop");

    expect(state.status).toBe("STARTING");
    expect(state.readiness.state).toBe("NOT_READY");
    expect(state.readiness.httpStatus).toBe(500);
    expect(state.readiness.evidence).toMatch(/curl exit 22/);
    expect(state.readiness.evidence).toMatch(/HTTP 500/);
  });

  it("reports RUNNING only after a probe observed the app answering, and shows what it saw", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    const state = await startLab("webgoat");

    expect(state.status).toBe("RUNNING");
    expect(state.readiness.state).toBe("READY");
    expect(state.readiness.httpStatus).toBe(200);
    expect(state.readiness.evidence).toMatch(/HTTP 200/);
    expect(state.readiness.evidence).toMatch(/from inside the sandbox network/);
    expect(state.readiness.observedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(state.detail).toMatch(/was served/);
  });

  it("converges from STARTING to RUNNING without recreating the container", async () => {
    const fake = fakeDocker({ answering: false });
    setLabDockerProvider(async () => fake.docker);

    expect((await startLab("dvwa")).status).toBe("STARTING");

    // The app finishes booting. Nothing else changes.
    fake.state.answering = true;

    const ready = await getLabState("dvwa");
    expect(ready.status).toBe("RUNNING");
    // Readiness is re-observed rather than cached: one container created and
    // started in total, two probes.
    expect(fake.calls.started).toHaveLength(1);
    expect(fake.calls.probes).toHaveLength(2);
  });

  it("reports UNKNOWN when the container is up but readiness cannot be observed", async () => {
    const fake = fakeDocker({ probeImage: false, probePullFails: true });
    setLabDockerProvider(async () => fake.docker);

    const state = await startLab("juice-shop");

    // Not RUNNING: nothing was observed serving. Not STARTING either: no probe
    // ran, so "not yet" would be a claim about the app we never tested.
    expect(state.containerRunning).toBe(true);
    expect(state.status).toBe("UNKNOWN");
    expect(state.status).not.toBe("STARTING");
    expect(state.readiness.state).toBe("UNVERIFIED");
    expect(state.readiness.observedAt).toBeUndefined();
    expect(state.readiness.evidence).toMatch(/not present locally/);
    expect(state.readiness.evidence).toMatch(new RegExp(labProbeImage().replace(/[.:]/g, "\\$&")));
  });

  it("probes with a sandboxed request to the lab's own internal address", async () => {
    const fake = fakeDocker({ answering: false });
    setLabDockerProvider(async () => fake.docker);

    await startLab("dvwa");

    expect(fake.calls.probes).toHaveLength(1);
    const probe = fake.calls.probes[0];
    expect(probe.Image).toBe(labProbeImage());
    // It asks the lab, at the address only the sandbox network resolves.
    expect(probe.Cmd.join(" ")).toContain("http://dvwa.lab:80");
    expect(probe.Cmd).toContain("--max-time");
    // And it is given no more privilege than a tool container: no published
    // port, read-only root, all capabilities dropped.
    expect(probe.HostConfig.NetworkMode).toBe(SANDBOX_NETWORK_NAME);
    expect(probe.HostConfig.PublishAllPorts).toBe(false);
    expect(probe.HostConfig.PortBindings).toBeUndefined();
    expect(probe.HostConfig.ReadonlyRootfs).toBe(true);
    expect(probe.HostConfig.CapDrop).toEqual(["ALL"]);
    expect(probe.HostConfig.SecurityOpt).toContain("no-new-privileges");
    expect(probe.HostConfig.Privileged).toBe(false);
    expect(probe.HostConfig.Binds).toEqual([]);
    expect(probe.HostConfig.Memory).toBeLessThanOrEqual(128 * 1024 * 1024);
    expect(probe.Labels["cyberguard.lab-probe"]).toBe("dvwa");
    // The probe does not outlive the question.
    expect(fake.calls.probesRemoved).toContain(probe.name);
  });

  it("does not probe a lab that has no running container", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    const stopped = await getLabState("webgoat");

    expect(stopped.status).toBe("STOPPED");
    expect(stopped.containerRunning).toBe(false);
    expect(stopped.readiness.state).toBe("NOT_READY");
    expect(stopped.readiness.evidence).toMatch(/nothing to probe/);
    expect(stopped.readiness.observedAt).toBeUndefined();
    expect(fake.calls.probes).toHaveLength(0);
  });

  it("reuses one probe for concurrent reads instead of racing on the container name", async () => {
    const fake = fakeDocker({
      existing: { "cyberguard_lab_dvwa": { running: true } },
    });
    // Hold the probe open so every caller is provably inside it before it can
    // finish. Nothing here depends on timing of the machine.
    let release!: () => void;
    fake.state.probeHold = new Promise<void>((resolve) => {
      release = resolve;
    });
    setLabDockerProvider(async () => fake.docker);

    const reads = Promise.all([
      getLabState("dvwa"),
      getLabState("dvwa"),
      listLabStates(),
    ]);
    for (let i = 0; i < 25; i++) await Promise.resolve(); // let all three arrive
    release();
    const [first, second, listed] = await reads;

    // One probe container, shared: a second container with the same name would
    // fail to create, and three probes would triple the cost of one read.
    const dvwaProbes = fake.calls.probes.filter(
      (p) => p.Labels["cyberguard.lab-probe"] === "dvwa",
    );
    expect(dvwaProbes).toHaveLength(1);
    expect(fake.calls.probesRemoved).toHaveLength(1);
    expect(first.readiness.state).toBe("READY");
    expect(second.readiness.observedAt).toBe(first.readiness.observedAt);
    expect(listed.find((l) => l.id === "dvwa")!.status).toBe("RUNNING");
  });
});

describe("stopping a lab", () => {
  it("removes the container and reports the state Docker now shows", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);
    await startLab("dvwa");

    const state = await stopLab("dvwa");

    expect(fake.calls.removed).toContain("cyberguard_lab_dvwa");
    expect(state.status).toBe("STOPPED");
    expect(state.containerRunning).toBe(false);
    // A stopped lab is not "starting": it is not serving, and here is why.
    expect(state.readiness.state).toBe("NOT_READY");
    expect(state.readiness.evidence).toMatch(/nothing to probe/);
  });

  it("is idempotent: stopping a lab that is already gone still succeeds", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    expect((await stopLab("juice-shop")).status).toBe("STOPPED");
    expect((await stopLab("juice-shop")).status).toBe("STOPPED");
  });

  it("surfaces an unreachable daemon instead of claiming the lab is stopped", async () => {
    setLabDockerProvider(async () => null);
    await expect(stopLab("juice-shop")).rejects.toThrow(/NOT_AVAILABLE/);
  });
});

describe("/api/labs", () => {
  it("lists every catalog lab with a real, explained status", async () => {
    setLabDockerProvider(async () => null);
    const app = await createApp();

    const res = await request(app).get("/api/labs").expect(200);

    expect(res.body.labs).toHaveLength(LAB_CATALOG.length);
    for (const lab of res.body.labs) {
      expect(lab).toHaveProperty("id");
      expect(lab).toHaveProperty("name");
      expect(lab).toHaveProperty("difficulty");
      expect(lab).toHaveProperty("internalUrl");
      expect(typeof lab.detail).toBe("string");
      expect(lab.detail.length).toBeGreaterThan(0);
      // The provider is deliberately unreachable for this whole suite, so the
      // only honest status is UNKNOWN. A 200 carrying STOPPED would mean the
      // list invented a container state it never read.
      expect(lab.status).toBe("UNKNOWN");
      // The two facts travel separately over the wire too.
      expect(lab.containerRunning).toBeNull();
      expect(lab.readiness.state).toBe("UNVERIFIED");
      expect(lab.readiness.evidence.length).toBeGreaterThan(0);
      expect(lab.readiness.probeImage).toBe(labProbeImage());
    }
  });

  it("never reports RUNNING for a lab whose app has not answered", async () => {
    const fake = fakeDocker({ answering: false });
    setLabDockerProvider(async () => fake.docker);
    const app = await createApp();
    asOperator();

    const started = await request(app)
      .post("/api/labs/dvwa/start")
      .set("x-api-key", OPERATOR_KEY)
      .expect(200);
    expect(started.body.status).toBe("STARTING");
    expect(started.body.containerRunning).toBe(true);

    const listed = (
      await request(app).get("/api/labs").set("x-api-key", OPERATOR_KEY).expect(200)
    ).body.labs as LabState[];
    expect(listed.find((l) => l.id === "dvwa")!.status).toBe("STARTING");
    expect(listed.some((l) => l.status === "RUNNING")).toBe(false);

    // Once the app answers, the same endpoint says so, and shows its evidence.
    fake.state.answering = true;
    const ready = await request(app)
      .get("/api/labs/dvwa")
      .set("x-api-key", OPERATOR_KEY)
      .expect(200);
    expect(ready.body.status).toBe("RUNNING");
    expect(ready.body.readiness.state).toBe("READY");
    expect(ready.body.readiness.httpStatus).toBe(200);
  });

  it("answers 404 for an id outside the catalog", async () => {
    setLabDockerProvider(async () => null);
    const app = await createApp();

    const res = await request(app).get("/api/labs/not-a-lab").expect(404);
    expect(res.body.error).toBe("UNKNOWN_LAB");
  });

  it("answers 503 with the reason when Docker is unreachable", async () => {
    setLabDockerProvider(async () => null);
    const app = await createApp();
    asOperator();

    const res = await request(app)
      .post("/api/labs/juice-shop/start")
      .set("x-api-key", OPERATOR_KEY)
      .expect(503);
    expect(res.body.error).toBe("NOT_AVAILABLE");
    expect(res.body.reason).toMatch(/Docker daemon is unreachable/);
  });

  it("refuses to start anything the catalog does not name", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);
    const app = await createApp();
    asOperator();

    await request(app)
      .post("/api/labs/alpine/start")
      .set("x-api-key", OPERATOR_KEY)
      .expect(400);
    expect(fake.calls.created).toHaveLength(0);
  });

  it("starts and stops a catalog lab through the API", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);
    const app = await createApp();
    asOperator();

    const started = await request(app)
      .post("/api/labs/juice-shop/start")
      .set("x-api-key", OPERATOR_KEY)
      .expect(200);
    expect(started.body.status).toBe("RUNNING");
    expect(fake.calls.created[0].HostConfig.PortBindings).toBeUndefined();

    const stopped = await request(app)
      .post("/api/labs/juice-shop/stop")
      .set("x-api-key", OPERATOR_KEY)
      .expect(200);
    expect(stopped.body.status).toBe("STOPPED");
  });
});
