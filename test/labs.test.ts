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
import { SANDBOX_NETWORK_NAME } from "../src/server/sandbox/network";
import { createApp } from "../server";

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
  } = {},
) {
  const containers: Record<string, { running: boolean; status?: string }> = {
    ...(opts.existing ?? {}),
  };
  const calls = {
    created: [] as any[],
    started: [] as string[],
    stopped: [] as string[],
    removed: [] as string[],
    pulled: [] as string[],
    networksCreated: [] as string[],
  };
  let imagePresent = opts.hasImage ?? true;

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
          if (!imagePresent) throw new Error(`no such image: ${image}`);
          return { Id: "sha256:fake" };
        },
      };
    },
    async pull(image: string) {
      calls.pulled.push(image);
      imagePresent = true;
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
      calls.created.push(cfg);
      containers[cfg.name] = { running: false };
      return {
        async start() {
          calls.started.push(cfg.name);
          containers[cfg.name] = { running: true };
        },
      };
    },
  };

  return { docker, calls, containers };
}

afterEach(() => setLabDockerProvider(null));

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
  it("reports RUNNING only while the container actually runs", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);

    expect((await startLab("juice-shop")).status).toBe("RUNNING");

    // Something outside the platform removes the container.
    delete fake.containers["cyberguard_lab_juice-shop"];

    const after = await getLabState("juice-shop");
    expect(after.status).toBe("STOPPED");
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

describe("stopping a lab", () => {
  it("removes the container and reports the state Docker now shows", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);
    await startLab("dvwa");

    const state = await stopLab("dvwa");

    expect(fake.calls.removed).toContain("cyberguard_lab_dvwa");
    expect(state.status).toBe("STOPPED");
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
    }
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

    const res = await request(app).post("/api/labs/juice-shop/start").expect(503);
    expect(res.body.error).toBe("NOT_AVAILABLE");
    expect(res.body.reason).toMatch(/Docker daemon is unreachable/);
  });

  it("refuses to start anything the catalog does not name", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);
    const app = await createApp();

    await request(app).post("/api/labs/alpine/start").expect(400);
    expect(fake.calls.created).toHaveLength(0);
  });

  it("starts and stops a catalog lab through the API", async () => {
    const fake = fakeDocker();
    setLabDockerProvider(async () => fake.docker);
    const app = await createApp();

    const started = await request(app).post("/api/labs/juice-shop/start").expect(200);
    expect(started.body.status).toBe("RUNNING");
    expect(fake.calls.created[0].HostConfig.PortBindings).toBeUndefined();

    const stopped = await request(app).post("/api/labs/juice-shop/stop").expect(200);
    expect(stopped.body.status).toBe("STOPPED");
  });
});
