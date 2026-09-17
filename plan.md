# CYBERGUARD AI — V2 Migration Plan & Status

> Working document. Last updated: **2026-09-17**.
> Resume point is [§3 — Next session](#3-next-session-start-here).
>
> §2 is new: an inspection on 2026-09-16 found that two claims in the previous
> revision of this file are **wrong**, and that the highest-value step was
> recorded as blocked when it is not. Nothing in §1's architecture claims
> changed; what changed is the evidence underneath them.
>
> 2026-09-17: Step A's first item is **done** (§2.3). Running it for real found
> three defects the reading had not: §2.7 (`RUNNING` is not "ready"), §2.8
> (`STOPPED` is returned when the truthful answer is "unknown"), and §2.9 (a
> stale dev-server process can answer for the next run and fake a pass).
>
> 2026-09-17 (later): **§2.8 is fixed and proven** — the lab API now answers
> `UNKNOWN` when it cannot read Docker, and the test whose title contradicted its
> own assertion was rewritten. §2.7 is the remaining open defect from that run.

---

## 1. Where we are

The V1 → V2 migration has run through 15 phases. The governing principle
throughout has been the one from §40 of the master prompt: **the platform must
never report a result that did not happen.** Most of the work has been removing
places where it did.

### Verification baseline — measured 2026-09-16

| Check | Result |
|---|---|
| `npm run lint` | **0 errors**, 50 warnings (`no-explicit-any` in tests + a few routes). The previous "eslint clean" overstated this — it is clean of *errors*, not of warnings. |
| `npm run test` | **260 passed / 0 failed — 22 of 22 files 🟢** — `npx vitest run --reporter=basic`, 2026-09-16, 92.13s. This is the first fully green run on this machine, and the count is reproducible because the two environment-coupled tests were fixed rather than the timeout raised (§2.1). Before Step 0 the same command read 252 passed / 5 failed. |
| `npm run build` | last known clean (not re-run 2026-09-16). |
| Step A item 1 — lab reporting path | **proved 2026-09-17** (§2.3): 12 of 12 reported fields equal to `docker inspect`, the "exists but not running" case and the "removed" case both read correctly, and two isolation claims (no host port, no network egress) held under probes run from outside the platform. |
| Lab status honesty (§2.8) | **fixed and proved 2026-09-17**: with a dead daemon every lab reports `UNKNOWN` with the reason instead of `STOPPED`; with a live daemon the same field reports the real container state. Measured on the real stack over HTTP, both directions. `test/labs.test.ts` 23/23. |

The 253-passed figure this table used to carry predates the two commits that
landed after the phase table below (phases 16 and 17), so it is stale in both
directions. Step 0 re-established the number above; it is the number to compare
against from now on.

### Committed phases

| # | Commit | What landed |
|---|---|---|
| 1 | `6aed9cf` | Agent Manager, tool registry, Agent/Skill/Tool contracts |
| 2 | `6d52755` | Real tool health probes, platform event bus, introspection APIs |
| 3 | `fe5efe4` | Policy-driven security gateway + **real human approval system** |
| 4 | `df5e3c9` | Sandbox hardening: dedicated network, tmpfs, per-tool limits |
| 5 | `7c55fa4` | `subfinder` + `nuclei` adapters |
| 6 | `f2cf088` | `semgrep` + `trivy` adapters behind a workspace boundary |
| 7 | `55b8214` | Real Web + Code agents, evidence-based chaining |
| 8 | `a0df991` | Findings engine + non-exploitative Validation agent |
| 9 | `c23622c` | Removed the last fabrication sources; security test suite |
| 10 | `88bdd18` | Postgres persistence, identities/roles, tamper-evident audit chain |
| 11 | `ffa2d4c` | Stopped the **frontend** claiming what the backend no longer claims |
| 12 | `96caaa1` | Tool Registry / Findings / Approvals pages |
| 13 | `f21cf7e` | Remediation + Reporting + Testing agents (pipeline complete) |
| 14 | `986a5d8` | Lab Manager: isolated vulnerable targets + Lab Targets page |
| 15 | `9ffd4a2` | Knowledge base: cited BM25 retrieval over the security corpus |
| 16 | `8ab3634` | Recorded the knowledge-base commit hash here |
| 17 | `4b01e4b` | Cited retrieval exposed over the API and the Knowledge Base UI (Step D, first item) |

### Security properties now enforced in code, not prose

- **No self-approval.** `/api/tools/execute` used to read `approved: true` off
  the request body — any caller able to invoke a high-risk tool could authorize
  it. Now the server mints an approval request, a human with the `approver` role
  decides it, and execution redeems a single-use token bound to that exact
  tool + target. The decider is the authenticated principal, not a name in the
  body.
- **Fail closed.** No Docker → `503 NOT_AVAILABLE` with the real reason, never a
  silent downgrade to simulated output. `DATABASE_URL` set but unreachable →
  startup aborts rather than quietly losing findings and audit records.
- **Detection ≠ vulnerability.** Every finding enters at `DETECTED` with
  confidence 0. The findings engine has *no code path* producing `CONFIRMED`;
  only the Validation agent can move one, and the model may only *lower*
  confidence (its penalty is clamped non-negative).
- **Self-test cannot cheat.** The Testing agent probes controls by attempting
  what must be refused. It holds no tools, consults no model, and burns any
  approval token it creates.
- **A lab is never reachable from the host.** Lab containers get no published
  ports, only the internal sandbox network, and their status is read from
  `docker inspect` rather than from a stored flag. *(Half of this is now proven
  against a real container — §2.3.)*
- **Knowledge is not evidence.** Retrieved reference material reaches the model
  labelled as class background. No code path lets it raise a confidence or
  promote a status, and remediation citations are re-derived from the retriever
  so a model cannot mint a source.

---

## 2. Inspection findings — 2026-09-16

Findings, not opinions. Each one names the command or file that produced it.

### 2.1 The honest-failure tests were environment-coupled, and hung where the daemon exists *(fixed in Step 0)*

`test/honest-failure.test.ts` has two tests that assert the platform refuses to
run when no executor exists. Both encode the premise as a comment — `// no daemon
in CI` — and set `SANDBOX_MODE=docker` so that a missing daemon makes
`resolveExecutor` throw `ToolNotAvailableError`.

On a machine where Docker **is** reachable (this one — §2.2) the premise is
false, so `executeTool` walks past the honest-failure branch and calls
`executor.run()`. `src/server/sandbox/docker.ts:146-151` then inspects
`docker.getImage(image)` and, when the image is absent, **pulls it from the
network**. No tool image is cached locally, so the test blocks on a real pull and
dies at the 5000 ms default:

```
× refuses to run a declared-only tool when simulation was not opted into  5019ms
× reports NOT_AVAILABLE with a real reason instead of exit code 0 …       5005ms
  → Test timed out in 5000ms.
```

This is not the machine being slow. It is two tests whose subject ("no reachable
executor") is being simulated by *the absence of an actuator*, so they can only
prove the contract in an environment that has none. They fail — silently, as a
timeout rather than a clear assertion — in exactly the environment where the
contract is most worth proving. Note also that both mutate `process.env` without
restoring it and rely on the next test to reset.

The 5 recorded failures this run were not all of this class: re-running the four
files involved today gave `approvals` 13 ✓, `knowledge` 26 ✓, `labs` 23 ✓,
`honest-failure` 2 ✗ of 5. Three of the five are run-order/timing flakes, two are
the structural problem above.

**Resolved 2026-09-16 (Step 0).** The premise is no longer borrowed from the
host. `test/honest-failure.test.ts` now mocks `dockerode` with a client whose
`ping()` rejects, so `DockerExecutor.isAvailable()` — the real probe, not a
stand-in — returns false on every machine, and `resolveExecutor()` refuses for a
stated reason. The file's own assertions were wrong in a second way worth
recording: the "declared-only" test used `subfinder`, which **does** have an
adapter, so it never tested the branch it named. It now uses `prowler` and
asserts `hasAdapter("prowler") === false` first; the `nmap` test asserts
`hasAdapter("nmap") === true` first, because the unavailable-executor branch is
only reachable for a tool the registry admits could have run. Both now also
assert the refusal carries no `exitCode` and no `rawOutput` — the actual claim.
`SANDBOX_MODE` is restored in `afterEach` (and deletes the variable rather than
assigning `undefined`, which would have set the literal string).

| | Before | After |
|---|---|---|
| `honest-failure` on a machine **with** Docker | 2 ✗ of 5, both 5000ms timeouts | **5 ✓ of 5**, 190ms total |
| `approvals` > the four-claim HTTP test | 3194ms of a 5000ms budget when idle; timed out under load | split into four, largest block **1057ms**; 16 ✓ in the file |
| full suite | 252 ✓ / 5 ✗ | **260 ✓ / 0 ✗**, 22 files, 92.13s |
| `testTimeout` | untouched | untouched — nothing is hidden behind a longer deadline |

### 2.2 The environment gap in §4 is closed

| Var | Previous revision of this file | Measured 2026-09-16 |
|---|---|---|
| Docker daemon | **not running** (`//./pipe/dockerDesktopLinuxEngine` — ENOENT) | **running** — `Docker version 29.6.2, build dfc4efb`; `docker info` → `29.6.2 Docker Desktop` |
| Postgres | not installed (`psql` not on PATH) | still not on PATH — but Docker can host one, which is what Step A asks for anyway |

Consequences: Step A is **not blocked**, and the "written but never executed"
ledger below is executable starting now. The corollary is §2.1: the suite's
green/red signal was *less* trustworthy than when the daemon was down — which is
why Step 0 was done before anything in Step A.

Local images on this daemon: `vulnerables/web-dvwa:latest` (935 MB),
`moby/buildkit:buildx-stable-1`, `aralink-b1-test`. **No tool image**
(`nmap`, `subfinder`, `nuclei`, `semgrep`, `trivy`) is cached, so the first real
tool run is a network pull of an unknown size — budget for that before calling
the first run a failure.

### 2.3 A lab container has actually started — §4 was wrong

The previous revision said *"No lab container has ever actually started."* The
artifacts left on this machine say otherwise:

```
container : cyberguard_lab_dvwa         ← the platform's own name
                                          (src/server/labs/manager.ts:99, `cyberguard_lab_${id}`)
image     : vulnerables/web-dvwa:latest
started   : 2026-09-01T15:33:52Z
finished  : 2026-09-14T12:18:30Z   ExitCode 255
logs      : "Starting MariaDB database server …" / "Starting Apache httpd web server"
            [Tue Sep 01 15:35:11 2026] Apache/2.4.25 (Debian) configured -- resuming normal operations
```

It booted, served, and ran for thirteen days, so the lab target itself works.
Its real `HostConfig` also **matches the posture the code declares** —
`NetworkMode=cyberguard_sandbox` (not the default bridge), `PortBindings={}`,
`Binds=[]`, `Privileged=false`, `SecurityOpt=[no-new-privileges]`,
`Memory=1 GiB`, `PidsLimit=512`. `ReadonlyRootfs=false` and `CapDrop=[]` are also
what `manager.ts` asks for: a deliberately vulnerable app has to write its own
root filesystem. Read-only rootfs + `CapDrop: ["ALL"]` are the *tool* posture,
not the lab posture — a distinction worth keeping straight in the README.

So Step A's first item was half done. The other half — whether the API reports
this state correctly — was executed on **2026-09-17** and is now **done**: the
lab was started through `POST /api/labs/dvwa/start` on this machine and every
field the API returns was compared against the daemon's own view of the same
container.

| `GET /api/labs/dvwa` | API said | `docker inspect cyberguard_lab_dvwa` | |
|---|---|---|---|
| *(before — the leftover)* `status` | `STOPPED` | `State.Running=false`, `Status=exited` | ✅ |
| *(before)* `detail` | `Container exists but is not running (exited).` | `ExitCode=255` | ✅ |
| *(before)* `containerId` | `2397a0d2ea23` | `Id` starts `2397a0d2ea23` | ✅ |
| *(before)* `startedAt` | `2026-09-01T15:33:52.496933732Z` | same string | ✅ |
| *(after start)* `status` | `RUNNING` | `State.Running=true` | ✅ |
| *(after start)* `containerId` | `07d2b14993ed` | `Id` starts `07d2b14993ed` | ✅ |
| *(after start)* `startedAt` | `2026-09-17T11:15:26.447071911Z` | same string, to the nanosecond | ✅ |
| `internalUrl` claim | `http://dvwa.lab:80` | `Aliases=[dvwa.lab dvwa]` on `NetworkMode=cyberguard_sandbox` | ✅ |
| posture the code declares | — | `PortBindings=map[]`, `PublishAllPorts=false`, `Binds=[]`, `Privileged=false`, `SecurityOpt=[no-new-privileges]`, `Memory=1073741824`, `PidsLimit=512`, `RestartPolicy=no`, `Hostname=dvwa`, `Labels={cyberguard.lab:dvwa, cyberguard.managed:true}` | ✅ |
| *(after stop)* `status` / `detail` | `STOPPED` / `No container exists for this lab.` | `docker inspect` → `no such object`; `docker ps -a` shows no `cyberguard_lab_*` | ✅ |

Twelve reported fields, twelve matches, **zero mismatches** — including the two
cases that would have been easy to get wrong: *"a container exists but is not
running"* is distinguished from *"no container exists"* rather than both reading
`STOPPED`, and the 12-character id and nanosecond timestamp are read from Docker
rather than reconstructed.

Two isolation claims were also checked from **outside** the platform, which is
what makes them evidence rather than restatement:

- **Nothing is published to the host.** `curl http://127.0.0.1:80` was refused
  before the lab started *and* while it was running (`http=000`), so the empty
  `PortBindings` is not just an inspect field.
- **The sandbox network really is internal.** From inside the running lab,
  `bash -c 'exec 3<>/dev/tcp/1.1.1.1/80'` → `Network is unreachable`.

Timings, recorded so the next run can be compared rather than guessed: first
`POST /start` **35.70s** (removing the leftover + create + start; the image was
already cached, so **no pull happened**), second `POST /start` **8.08s**, `POST
/stop` **8.21s** and **6.57s**. The 35.7s-vs-8.1s spread is not explained by an
image pull and is recorded as an observation, not a cause.

Starting the lab also **removed the leftover container it replaced** —
`startLab` deletes a stopped leftover before creating, and `docker inspect`
afterwards confirms `no such object`. That is what this file predicted; what it
still cannot explain is Step A item 4 (`ExitCode 255`).

### 2.4 The README describes a platform two phases out of date

`README.md` — agent runtime section:

- It says the other **nine** catalog agents are not executable and that
  `/api/agents` "lists only the **three** above". Its own table above that
  sentence lists four. Reality, from `src/server/agents/index.ts` and
  `GET /api/agents` (`server.ts:526`, `agentManager.list()`): **seven** are
  registered — `recon`, `web_security`, `code_security`, `validation`,
  `remediation`, `reporting`, `testing` — and six catalog entries are not
  (`vuln_analysis`, `network_security`, `cloud_security`, `container_security`,
  `digital_forensics`, `threat_intel`).
- Related: `validation` is executable but **absent from the twelve-agent catalog**
  in `src/data/agentPlatformData.ts`, so the catalog and the runtime disagree
  about what exists in both directions.

This is the failure mode the project exists to remove, in the project's own
documentation: a claim that was true at phase 8 (when three agents existed) and
was never revisited when phases 13–14 added four more.

### 2.5 `data set.txt` is unreferenced, untracked, and about to become another stale doc

`data set.txt` (untracked, `git status` → `??`) lists twelve GitHub repositories
under three headings, plus a line naming `sundowndev/hacker-roadmap` as
"المصدر الأساسي الذي فحصناه" — the primary source this project was based on.
Nothing in `src/` or `README.md` refers to it. Of the twelve: **two are already
implemented** (`nmap`, `nuclei`), ten are not, and three of those ten could not
run under the current isolation posture at all. Decision and per-entry reading
in §5.

### 2.6 `docs/` is stale by construction

`docs/` holds four Arabic documents dated 29–30 August — `Architecture Review`
(HTML + PDF), `Technical Review`, `roadmap-report.html`. All predate **all
fifteen** phases. `roadmap-report.html` still marks `PHASE 1 = NEXT`. They are
not wrong about a small thing; they describe a different platform. They are
deliberately left alone for now (§3, Step 4) — refreshing four documents that no
code references is cosmetic work, while §2.4 is a *false claim about the present*
and gets fixed first. This file is the living plan, which is why today's findings
went here and not into a fifth document in `docs/`.

### 2.7 `RUNNING` is not "ready" — measured, and nothing reports the difference

Step A item 1 was satisfied by every field comparison above, and still left the
platform saying something a reader can misread. Measured on the second start:

| Moment | Time from `State.StartedAt` |
|---|---|
| `POST /api/labs/dvwa/start` returns `status: RUNNING` | **+12s** (request itself 8.08s) |
| `docker logs` — Apache *"resuming normal operations"* | **+29s** |
| the app actually answers `127.0.0.1:80` from inside the container | **+33s** |

So for roughly **21–25 seconds** the API reported `RUNNING` about a target that
could not be reached. The `detail` string is literally true (*"Container is
running on the cyberguard_sandbox network"*) — the problem is the field is named
`status`, and `RUNNING` reads as "the lab is up". `STARTING` is declared in
`LabStatus` and never returned by any path.

Not fixed here on purpose: Step A is a proof step, and closing this needs a
decision (a readiness probe against the lab's own port, or a separate `ready`
boolean with its own honest values) rather than a one-line edit. An agent that
starts a lab and immediately scans it will scan a closed port and record a false
negative — which is the failure this project exists to remove.

### 2.8 `STOPPED` was returned when the truthful answer is "unknown" — ✅ **FIXED 2026-09-17**

**The defect.** With `DOCKER_HOST` pointed at a dead endpoint (own `PORT`,
listening PID checked before believing the response — see §2.9), the first run of
this check produced a self-contradicting pair of answers:

```
GET /api/labs/dvwa         →  status: "STOPPED"
                              detail: "NOT_AVAILABLE: tool \"lab-manager\" cannot be executed — the
                                       Docker daemon is unreachable, so no lab can be started or inspected"
POST /api/labs/dvwa/start  →  503 NOT_AVAILABLE with the reason, and no container created
```

The 503 is right: the platform refuses and says why. `status: "STOPPED"` is not.
No container state was ever read, so the platform was asserting something it did
not know. `LabStatus` already declared `UNKNOWN` for exactly this case, but
`UNKNOWN` and `STARTING` were dead members: nothing ever returned them.

**The fix.** One line in `src/server/labs/manager.ts` — the `dockerOrThrow()`
catch in `getLabState` now returns `UNKNOWN` with the reason, instead of
`STOPPED`. `RUNNING`/`STOPPED` still come only from a real `docker inspect`, so
nothing that used to be observed is now guessed; the change only affects the
path where nothing could be observed at all. The `LabStatus` doc comment and the
route comment in `server.ts` now state the rule: *"not observed" is not "off".*

The UI needed no change — `LabsManager.tsx` already rendered `UNKNOWN` as its own
rose chip with the backend's `detail` shown verbatim; the backend simply never
sent it. `POST /start` still refuses with 503 (it was never the wrong half) and
`startLab`'s idempotency check is unaffected, because `UNKNOWN !== "RUNNING"`
falls through to the refusal rather than to a false "already running".

**The test that contradicted its own title.** `test/labs.test.ts:269` was titled
*"says the daemon is unreachable rather than inventing a status"* and then
asserted `expect(state.status).toBe("STOPPED")` — the assertion, not the title,
is what ran. It is now titled `"says UNKNOWN when the daemon is unreachable,
rather than inventing a status"` and asserts `UNKNOWN`, `not.toBe("STOPPED")`,
and that `containerId` and `startedAt` stay undefined. Two more assertions were
added where the unreachable provider was already being used silently:
`listLabStates()` and the `GET /api/labs` handler must both say `UNKNOWN` for
every lab, so a regression to `STOPPED` fails the unit path **and** the HTTP path.

**Proved on the real stack, both directions, same URL** (own `PORT` per run,
listening PID confirmed via `netstat -ano | grep LISTENING`, service stopped after
each run — the §2.9 rule):

| Run | `GET /api/labs` | `POST /api/labs/juice-shop/start` |
|---|---|---|
| live daemon (port 7831) | all three labs **`STOPPED`** — `"No container exists for this lab."` | *(not exercised — nothing to start)* |
| dead daemon (port 7832) | all three labs **`UNKNOWN`** — `NOT_AVAILABLE: … the Docker daemon is unreachable …` | **503**, `{"error":"NOT_AVAILABLE","reason":"the Docker daemon is unreachable, so no lab can be started or inspected"}` |

That contrast is the whole point: the same field stops claiming a state the
platform could not read, while the readable case keeps reporting the container
state it genuinely observed. `test/labs.test.ts` — **23 passed**, 9.98s.
`npx tsc --noEmit` clean; `eslint` on the four touched files: 0 errors, 9
pre-existing `no-explicit-any` warnings.

### 2.9 The method produced a false signal twice — record the rule

The dev server is started as `npx tsx server.ts &`, and killing `$!` kills the
`npx` wrapper rather than the `node` child. The surviving instance keeps port
7799 and then **answers for the next run**: one verification attempt logged
`EADDRINUSE` while my requests were served by the stale server, so a
`DOCKER_HOST`-based check silently tested the wrong process. It looked like the
check had passed.

This is the same class of defect as §2.1 — a signal that does not mean what it
appears to mean — and this time it was in the verification method, not the
product. Rule for the remaining Step A items: **give each run its own `PORT` and
confirm the listening PID (`netstat -ano | grep LISTENING`) before believing any
response.**

---

## 3. Next session (start here)

Ordered. Each step ends with `npm run lint && npm run test` and its own commit.

### Step 0 — Make the test suite tell the truth about this machine — ✅ **DONE 2026-09-16**
A green suite is the precondition for proving anything in Step A, and it could not
be trusted in either direction (§2.1).
- [x] Stop encoding "no daemon" as the premise. `test/honest-failure.test.ts` now
      mocks `dockerode` with an unreachable client, so
      `resolveExecutor → ToolNotAvailableError` is asserted as a **unit property**
      that holds identically whether or not the host runs Docker. No
      `testTimeout` was raised — that would hide a real image pull behind a green
      check, which is what it was doing before. `2 ✗ → 5 ✓`, 190ms.
- [x] Restore `SANDBOX_MODE` in `afterEach`, and `delete` it rather than assign
      `undefined` (the latter sets the literal string "undefined").
- [x] One reproducible full-suite number recorded in §1, with the command that
      produced it: **260 passed / 0 failed**, 22 files,
      `npx vitest run --reporter=basic`. Getting there also required splitting the
      one over-loaded `approvals` test (§Test-suite weaknesses); nothing skips and
      no timeout was raised.

### Step A — Prove what is written *(unblocked as of 2026-09-16 — §2.2)*
- [x] **DONE 2026-09-17** — start a lab from `/api/labs/:id/start` and compare
      every reported field with `docker inspect`: **12/12 matched**, including the
      nanosecond `startedAt` and the 12-character id, with "container exists but
      is not running" and "no container exists" correctly distinguished, plus two
      isolation probes run from outside the platform. Table and numbers in §2.3.
      Defects found while executing: §2.7, §2.8 (**fixed 2026-09-17**), §2.9.
- [ ] Run `nmap` against the lab over the internal network and confirm
      `result.sandbox` matches reality. First run pulls an image — record the pull
      separately from the run.
- [ ] Run Postgres (container is fine) and start the server with `DATABASE_URL`
      set, so the migrations and the audit chain execute against a real server
      for the first time.
- [x] **Leftover container: gone on 2026-09-17**, and not by hand — `startLab`
      removed it as this file predicted (`docker inspect` → `no such object`).
- [ ] **`ExitCode 255`: still unexplained**, and no longer investigable on this
      machine, because that leftover was the only artifact and it is gone. If it
      recurs, capture `docker inspect --format '{{.State.Error}}'` and the
      daemon's `events` around the stop *before* anything removes the container.
      Host shutdown remains the likely cause and is still only a likelihood.
- [ ] Record the outcome here — **including anything that turns out to be wrong.**
      This step converts §4's "written" column into "proven".

### Step 1 — Correct the false claims *(cheap, and it is the project's own principle)*
- [x] **§2.8 done 2026-09-17, ahead of this step** because it was a one-line
      contract fix, not a design decision: the lab API answers `UNKNOWN` instead
      of `STOPPED` when it cannot read Docker, and the test whose title
      contradicted its assertion was rewritten. Evidence in §2.8.
- [ ] §2.7 (`RUNNING` reported ~21–25s before the lab actually answers) is still
      open and *is* a design decision: a readiness probe against the lab's own
      port, or a separate `ready` field. Not to be rushed.
- [ ] `README.md`: seven executable agents, six catalog-only, and note that
      `validation` is executable but not in the catalog (§2.4).
- [ ] Decide the catalog/runtime disagreement rather than documenting it: either
      add `validation` to `agentPlatformData.ts` or state why the catalog is a
      different list.
- [ ] `docs/` banner: one line on each of the four documents stating the date and
      the phase range they describe, so a reader cannot mistake them for current.
      Full refresh is not in scope here.

### Step 2 — ZAP adapter (still blocked on a design decision)
The plan was `src/server/tools/zap.ts` at HIGH risk with a separately-approved
active scan. **The blocker found while scoping it stands:** `zap-baseline.py`
writes its JSON report to a file under `/zap/wrk`, but sandboxed tools run with a
read-only root filesystem, a single tmpfs, and only stdout captured (verified in
`src/server/sandbox/docker.ts` — `ReadonlyRootfs: true` at :164, the single
`Tmpfs` mount at :166, `CapDrop: ["ALL"]` at :171). So:

- [ ] Decide the mechanism first. Either (a) give the sandbox a per-run writable
      artifacts directory that the executor reads declared report files back
      from, or (b) keep ZAP declared-only until (a) exists. Do not ship an
      adapter whose report path cannot work.
- [ ] If (a): the writable bind is a change to the isolation posture and needs
      its own tests — fresh temp dir per run, outside the workspace, removed
      afterwards, never the workspace or the Docker socket.
- [ ] Split the risk rather than trusting a parameter: `zap` (baseline/passive,
      HIGH) and `zap-active` (CRITICAL, lab-only, `ENABLE_CRITICAL_TOOLS`).
      Approval tokens bind to a tool id, so a baseline approval then cannot be
      redeemed for an active scan — which a `mode` parameter would allow.
- [ ] Every alert emits `validated: false`.

### Step 3 — MCP integration (§25)
- [ ] Expose tools over MCP **through** the existing gateway — `executeTool` is
      the only entry point, so MCP inherits scope checks, risk policy, approval
      and audit automatically.
- [ ] Hard requirement: MCP must not create a second path to tool execution.
      Add a test asserting an MCP-originated call is refused for an
      out-of-scope target exactly like a REST call.
- [ ] Commit: `feat(mcp): expose tools via MCP without bypassing the gateway`.

### Step 4 — Optional follow-ups
- [x] `GET /api/knowledge/search` + a search panel on the Knowledge Base page
      *(done — `4b01e4b`)*
- [ ] Widen the corpus: it currently covers **A01–A05 only** and **four MITRE
      tactics** (`TA0043`, `TA0001`, `TA0002`, `TA0004` in
      `src/data/cyberData.ts`), because that is all `src/data` contains. §5 is
      the scoping input to do this deliberately.
- [ ] `docs/` refresh, if it is still wanted once Steps 0–1 have landed.

---

## 4. Known limits — read before claiming anything works

This is the honest ledger. It matters more than the feature list.

### Written but never executed against real infrastructure

| Component | Status |
|---|---|
| `nmap`, `subfinder`, `nuclei`, `semgrep`, `trivy` adapters | Argument building and output parsing are unit-tested against sample output. **No adapter has ever run inside a real container.** No tool image is cached locally, so the first run also includes a pull. |
| Postgres layer | Migrations, SQL shape, parameterization and fail-closed behavior are tested (fake pool + a real `pg` connection attempt). **No statement has ever run against a live Postgres server.** |
| Lab Manager | Tested against a **fake Docker client** that records the container-create options. **Corrected 2026-09-16:** a real lab container *did* start (`cyberguard_lab_dvwa`, 2026-09-01 → 2026-09-14) and its real `HostConfig` matched the declared posture — but nothing has verified the API's reporting path or that a tool reached it. |

**The single highest-value next action is still not more code.** Step 0 (make the
suite's signal trustworthy) is done as of 2026-09-16; **Step A** (convert
"written" into "proven") is next. Everything else is building on unverified
foundations.

### Environment, measured 2026-09-16
- Docker daemon: **running** (29.6.2, Docker Desktop).
- Postgres: `psql` **not on PATH**; use a container.
- One leftover container: `cyberguard_lab_dvwa` (Exited 255 since 2026-09-14).
- No tool images cached; `vulnerables/web-dvwa:latest` is cached.
- `npm run test` costs ~25 s for four small files on this machine, so a full run
  is minutes, not seconds. That is a fact to design the suite around, not to
  paper over with a longer timeout.

### Knowledge base limits
- The corpus is **five OWASP entries (A01–A05) and four MITRE tactics** — that
  is everything `src/data/cyberData.ts` holds. Retrieval cannot answer about
  what is not there, and correctly returns nothing instead of guessing.
- Retrieval is **lexical (BM25)**, so it misses synonyms and Arabic morphology:
  a query using a different word form than the corpus scores zero. The coverage
  rule that suppresses one-common-word matches also costs recall — a chunk
  matching a single, genuinely relevant term is dropped along with the noise.
- There is **no CWE text**; CWE ids are indexed for exact lookup only.

### Deliberately not implemented
- `zap`, `prowler`, `volatility` — declared in the registry, correctly reporting
  `NOT_IMPLEMENTED` rather than pretending. See Step 2 for why `zap` is still in
  this list.
- Six of the twelve catalog agents remain UI entries; `/api/agents` lists the
  seven that are executable (§2.4). Keeping this list at three numbers that
  disagree is how the README drifted in the first place.

### Carried-over weaknesses
- `APP_ACCESS_KEY` ships in the client bundle via `VITE_APP_ACCESS_KEY`. It is a
  coarse gate, not an auth boundary — documented in the README. `API_PRINCIPALS`
  is the real mechanism; put a proper auth proxy in front for any real
  deployment.
- Projects, circuit breakers and recovery history are still in-memory even with
  Postgres configured; only findings, audit entries and agent runs write
  through.
- Approval tokens bind to tool + target, **not to parameters**. For the current
  tools that is sufficient because each descriptor caps its own arguments, but
  it is the reason Step 2 splits ZAP into two tool ids instead of trusting a
  `mode` parameter.

### Test-suite weaknesses *(all resolved 2026-09-16 — §2.1)*
- ~~The suite's honesty tests depend on the host's Docker state.~~ **Fixed:** the
  unreachable daemon is injected, so the check is identical with or without
  Docker on the host.
- ~~`SANDBOX_MODE` is mutated per test and restored inconsistently.~~ **Fixed:**
  restored in `afterEach`.
- ~~`test/approvals.test.ts > 428 opens a real approval request…` drives four
  sequential HTTP requests inside the 5000ms default and times out on this
  machine.~~ **Fixed by splitting, not by waiting longer.** It carried four
  separate claims (the 428 shape, the decision minting a token, the token
  authorizing a run, single use) in one timed block. Measured on an idle machine
  it took **3194ms of its 5000ms budget** before the suite loaded the box, which
  is why it failed as a bare timeout naming none of the four. It is now four
  tests, none exceeding two HTTP requests, and the largest measures **1057ms** —
  16 ✓ in the file, up from 13. The new tests also assert what the old one left
  implicit: the 428 leaks no token, the opened request is discoverable via
  `/api/approvals` by the approver, `decidedBy` is the authenticated principal,
  and the 200 for a `zap` run says `sandbox.mode: "local-sim"` instead of
  reading as a real ZAP scan.
- `test/setup.ts` pins `SANDBOX_MODE ??= "simulate"` and blanks the model keys,
  which is the right instinct; the tests above override it deliberately — now
  without depending on the machine.

---

## 5. `data set.txt` — decision and per-entry reading

**Decision: keep it as a scoping inventory, do not turn it into registry
entries.** Reasons, in order of weight:

1. It would grow the "declared but never runs" surface from **3 to 12**. The
   registry's declared-only bucket is supposed to be an honest `NOT_IMPLEMENTED`,
   not a wish list — and §4 says the bottleneck is proving what exists, not
   adding claims.
2. Three entries cannot run under this sandbox **by construction** (see table),
   so declaring them would be declaring something the platform already knows is
   impossible. That is the exact class of claim the project removed in phase 9.
3. Two are offensive (sqlmap, XSStrike) at CRITICAL risk, while the platform's
   own Validation agent is deliberately non-exploitative. They are not
   impossible to add — risk policy can gate them — but they pull against a design
   decision and deserve an explicit yes, not a silent import from a link list.

| Entry | Reading |
|---|---|
| `nmap`, `nuclei` | **Already implemented.** The file adds nothing here. |
| `theHarvester`, `ctfr`, `PhoneInfoga` | Fits the existing adapter contract (stdout-parsed, descriptor-scoped). The real question is **egress**: the sandbox network is `internal` unless `SANDBOX_ALLOW_EGRESS=true`, and all three are OSINT tools whose value *is* the internet. Either they run egress-enabled (a posture change that needs its own review) or they are lab-only and mostly useless. Decide that before writing an adapter. |
| `wfuzz` | Fits the same shape as `nuclei` (web fuzzing against a lab target), HIGH risk. The most credible new adapter of the ten. |
| `sqlmap`, `XSStrike` | CRITICAL, exploitation-grade. Tension with the non-exploitative validation design — see reason 3. |
| `wireshark` | Capture needs host network + `NET_RAW`/`NET_ADMIN`; tool runs get `CapDrop: ["ALL"]` and no host namespace. **Structurally infeasible here.** `tshark` over a pcap *file* would be feasible, but that is a different tool from the one listed. |
| `aircrack-ng` | Needs a physical wireless interface in monitor mode — a container cannot have one without host netns and device passthrough. **Structurally infeasible here.** |
| `bettercap` | Needs `NET_RAW`/`NET_ADMIN` + host netns for ARP spoofing/MITM. **Structurally infeasible here**, and offensive besides. |
| `hacker-roadmap` | Not a tool. Its listed role — "المصدر الأساسي الذي فحصناه" — is a **documentation** claim, and a bigger one than it looks: it says the platform's conceptual base is a community link list. Worth deciding explicitly rather than leaving it in a text file. |

Also to decide, because leaving it untracked and unreferenced is how §2.6
happened:
- [ ] Track `data set.txt` in git (it is now referenced from this section), or
      delete it. Untracked-and-unreferenced is the only option that guarantees a
      stale artifact.

---

## 6. Useful commands

```bash
npm run dev                    # server + Vite on :7799
npm run lint                   # tsc --noEmit && eslint  (0 errors, ~50 warnings)
npm run test                   # vitest — 260 passed / 0 failed, 22 files (§1)
npm run build && npm start     # production bundle

# Run a mission end to end against the lab target
curl -s -X POST localhost:7799/api/orchestrator/run-mission \
  -H 'Content-Type: application/json' \
  -d '{"userPrompt":"assess the staging host","target":"192.168.1.50"}'

# Real tool state — never a catalog claim
curl -s localhost:7799/api/tools/health

# Lab state, read from Docker
curl -s localhost:7799/api/labs
curl -s -X POST localhost:7799/api/labs/juice-shop/start

# Persistence posture
curl -s localhost:7799/api/database/status

# Environment facts this file depends on
docker info --format '{{.ServerVersion}} {{.OperatingSystem}}'
docker ps -a --format '{{.Names}} {{.Status}}'
docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}'
docker inspect cyberguard_lab_dvwa --format '{{.State.ExitCode}} {{.State.FinishedAt}}'
```

### Env worth knowing
| Var | Effect |
|---|---|
| `SANDBOX_MODE` | `auto`/`docker` fail closed; `simulate` opts into labelled fake output |
| `DATABASE_URL` | set → Postgres required; unset → in-memory, and it says so |
| `API_PRINCIPALS` | `id:roles:secret` — `approver` role is required to approve |
| `ENABLE_CRITICAL_TOOLS` | CRITICAL tools stay disabled unless listed here |
| `SANDBOX_WORKSPACE_ROOT` | the only directory code scanners may read |
| `SANDBOX_DOCKER_PING_TIMEOUT_MS` | deadline on the daemon probe (default 2000) |
