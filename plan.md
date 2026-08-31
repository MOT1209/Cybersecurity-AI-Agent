# CYBERGUARD AI — V2 Migration Plan & Status

> Working document. Last updated: **2026-08-31**.
> Resume point is [§3 — Next session](#3-next-session-start-here).

---

## 1. Where we are

The V1 → V2 migration has run through 13 phases. The governing principle
throughout has been the one from §40 of the master prompt: **the platform must
never report a result that did not happen.** Most of the work has been removing
places where it did.

### Verification baseline (all green at last run)

| Check | Result |
|---|---|
| `npm run test` | **208 passed** (20 files) |
| `npm run lint` | **0 errors**, 46 warnings (all `no-explicit-any`, pre-existing) |
| `npm run build` | clean |

Tests grew from **48 → 208** across the migration.

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

---

## 2. Uncommitted work in progress

**Lab Manager (§17)** — written, typechecks and lints clean, **but has no tests
and is not committed.**

```
?? src/server/labs/manager.ts     ← catalog + start/stop/inspect
 M server.ts                      ← /api/labs routes (list, get, start, stop)
 M src/server/sandbox/docker.ts   ← getDockerClient() exposed for the manager
```

Design decisions already made in that code:

- Labs run on the **internal sandbox network with NO published host ports**. A
  deliberately vulnerable app reachable from the host is an incident, not a lab.
- The catalog is a **fixed allowlist of pinned images** (Juice Shop, DVWA,
  WebGoat). A caller supplies an id, never an image reference — accepting one
  would be remote code execution by API.
- Status is **read from Docker**, never assumed. A lab whose container is gone
  reports `STOPPED`.

> **Decision needed:** leave uncommitted, or commit as WIP marked unverified.
> Current state: left uncommitted, deliberately, because the repo rule is that
> tests pass before a commit.

---

## 3. Next session (start here)

Ordered. Each step ends with `npm run lint && npm run test` and its own commit.

### Step 1 — Finish the Lab Manager
- [ ] Write `test/labs.test.ts` using a fake Docker client (same pattern as
      `test/database.test.ts` uses a fake `PgPool`).
- [ ] Assert the properties that matter: no `PortBindings` is ever set; only
      catalog ids are accepted; an unknown id is rejected; status comes from
      inspect rather than from a stored flag; `stopLab` is idempotent.
- [ ] Add a Labs page to the UI reading `/api/labs`, showing real status.
- [ ] Commit: `feat(labs): add lab manager for isolated vulnerable targets`.

### Step 2 — ZAP adapter
- [ ] `src/server/tools/zap.ts`. Risk stays **HIGH**, so it requires an approval
      token — the approval flow is already built and tested.
- [ ] Baseline/passive scan only by default; active scan behind an explicit,
      separately-approved parameter.
- [ ] Parse the JSON report; every alert emits `validated: false`.
- [ ] Commit: `feat(tools): add OWASP ZAP adapter behind mandatory approval`.

### Step 3 — Knowledge base / RAG (§24)
- [ ] `src/server/knowledge/` — ingestion, chunking, a local embedding-free
      retriever first (BM25-style keyword scoring) so it works with no API key.
- [ ] Seed from the OWASP/MITRE/CWE data already in `src/data/cyberData.ts`
      rather than fetching at runtime.
- [ ] **Every retrieved chunk must carry its source.** An agent citing
      knowledge without provenance is the same failure class as a finding
      without evidence.
- [ ] Wire into the Validation and Remediation agents as *context*, never as a
      basis for confirming a finding.
- [ ] Commit: `feat(knowledge): add cited retrieval over the security corpus`.

### Step 4 — MCP integration (§25)
- [ ] Expose tools over MCP **through** the existing gateway — `executeTool` is
      the only entry point, so MCP inherits scope checks, risk policy, approval
      and audit automatically.
- [ ] Hard requirement: MCP must not create a second path to tool execution.
      Add a test asserting an MCP-originated call is refused for an
      out-of-scope target exactly like a REST call.
- [ ] Commit: `feat(mcp): expose tools via MCP without bypassing the gateway`.

---

## 4. Known limits — read before claiming anything works

This is the honest ledger. It matters more than the feature list.

### Written but never executed against real infrastructure

| Component | Status |
|---|---|
| `nmap`, `subfinder`, `nuclei`, `semgrep`, `trivy` adapters | Argument building and output parsing are unit-tested against sample output. **No adapter has ever run inside a real container.** |
| Postgres layer | Migrations, SQL shape, parameterization and fail-closed behavior are tested (fake pool + a real `pg` connection attempt). **No statement has ever run against a live Postgres server.** |
| Lab Manager | Not tested at all yet. |

**The single highest-value next action is not more code — it is starting Docker
and Postgres on this machine** and converting the above from "written" to
"proven". Everything else is building on unverified foundations.

### Environment gaps on the dev machine
- Docker daemon: **not running** (`//./pipe/docker_engine` — ENOENT).
- Postgres: **not installed**.

### Deliberately not implemented
- `prowler`, `volatility` — declared in the registry, correctly reporting
  `NOT_IMPLEMENTED` rather than pretending.
- Nine of the twelve catalog agents remain UI entries; `/api/agents` lists only
  the seven that are executable.

### Carried-over weaknesses
- `APP_ACCESS_KEY` ships in the client bundle via `VITE_APP_ACCESS_KEY`. It is a
  coarse gate, not an auth boundary — documented in the README. `API_PRINCIPALS`
  is the real mechanism; put a proper auth proxy in front for any real
  deployment.
- Projects, circuit breakers and recovery history are still in-memory even with
  Postgres configured; only findings, audit entries and agent runs write
  through.
- 46 `no-explicit-any` lint warnings, mostly pre-existing in the frontend and in
  `localPlan.ts`.

---

## 5. Useful commands

```bash
npm run dev                    # server + Vite on :7799
npm run lint                   # tsc --noEmit && eslint
npm run test                   # vitest (208 tests)
npm run build && npm start     # production bundle

# Run a mission end to end against the lab target
curl -s -X POST localhost:7799/api/orchestrator/run-mission \
  -H 'Content-Type: application/json' \
  -d '{"userPrompt":"assess the staging host","target":"192.168.1.50"}'

# Real tool state — never a catalog claim
curl -s localhost:7799/api/tools/health

# Persistence posture
curl -s localhost:7799/api/database/status
```

### Env worth knowing
| Var | Effect |
|---|---|
| `SANDBOX_MODE` | `auto`/`docker` fail closed; `simulate` opts into labelled fake output |
| `DATABASE_URL` | set → Postgres required; unset → in-memory, and it says so |
| `API_PRINCIPALS` | `id:roles:secret` — `approver` role is required to approve |
| `ENABLE_CRITICAL_TOOLS` | CRITICAL tools stay disabled unless listed here |
| `SANDBOX_WORKSPACE_ROOT` | the only directory code scanners may read |
