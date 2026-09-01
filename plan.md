# CYBERGUARD AI — V2 Migration Plan & Status

> Working document. Last updated: **2026-09-01**.
> Resume point is [§3 — Next session](#3-next-session-start-here).

---

## 1. Where we are

The V1 → V2 migration has run through 15 phases. The governing principle
throughout has been the one from §40 of the master prompt: **the platform must
never report a result that did not happen.** Most of the work has been removing
places where it did.

### Verification baseline (all green at last run)

| Check | Result |
|---|---|
| `npm run test` | **253 passed** (22 files) |
| `npm run lint` | **0 errors** (`tsc --noEmit` + eslint clean) |
| `npm run build` | clean |

Tests grew from **48 → 253** across the migration.

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
  `docker inspect` rather than from a stored flag.
- **Knowledge is not evidence.** Retrieved reference material reaches the model
  labelled as class background. No code path lets it raise a confidence or
  promote a status, and remediation citations are re-derived from the retriever
  so a model cannot mint a source.

---

## 2. Uncommitted work in progress

None. The working tree is clean as of the last commit in the table above.

---

## 3. Next session (start here)

Ordered. Each step ends with `npm run lint && npm run test` and its own commit.

### Step A — Prove what is written (highest value)
- [ ] Start Docker Desktop, then verify against a real daemon: start a lab from
      `/api/labs/:id/start`, run `nmap` against it, and confirm the sandbox
      posture reported in `result.sandbox` matches reality.
- [ ] Run a Postgres container and start the server with `DATABASE_URL` set, so
      the migrations and the audit chain execute against a real server for the
      first time.
- [ ] Record the outcome here — including anything that turns out to be wrong.
      This step converts §4's "written" column into "proven".

### Step B — ZAP adapter (blocked on a design decision)
The plan was `src/server/tools/zap.ts` at HIGH risk with a separately-approved
active scan. **A blocker was found while scoping it:** `zap-baseline.py` writes
its JSON report to a file under `/zap/wrk`, but sandboxed tools run with a
read-only root filesystem, a single tmpfs, and only stdout captured. So:

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

### Step C — MCP integration (§25)
- [ ] Expose tools over MCP **through** the existing gateway — `executeTool` is
      the only entry point, so MCP inherits scope checks, risk policy, approval
      and audit automatically.
- [ ] Hard requirement: MCP must not create a second path to tool execution.
      Add a test asserting an MCP-originated call is refused for an
      out-of-scope target exactly like a REST call.
- [ ] Commit: `feat(mcp): expose tools via MCP without bypassing the gateway`.

### Step D — Optional follow-ups
- [ ] A `/api/knowledge/search` endpoint + wiring the Knowledge Base page to it,
      so a human can query the same corpus the agents read.
- [ ] Widen the corpus: it currently covers **A01–A05 only** (five of the OWASP
      Top 10) and four MITRE tactics, because that is all `src/data` contains.

---

## 4. Known limits — read before claiming anything works

This is the honest ledger. It matters more than the feature list.

### Written but never executed against real infrastructure

| Component | Status |
|---|---|
| `nmap`, `subfinder`, `nuclei`, `semgrep`, `trivy` adapters | Argument building and output parsing are unit-tested against sample output. **No adapter has ever run inside a real container.** |
| Postgres layer | Migrations, SQL shape, parameterization and fail-closed behavior are tested (fake pool + a real `pg` connection attempt). **No statement has ever run against a live Postgres server.** |
| Lab Manager | Tested against a **fake Docker client** that records the container-create options, so "no published ports" and "catalog ids only" are checked facts. **No lab container has ever actually started.** |

**The single highest-value next action is not more code — it is starting Docker
and Postgres on this machine** and converting the above from "written" to
"proven". Everything else is building on unverified foundations.

### Environment gaps on the dev machine
- Docker daemon: **not running** (`//./pipe/dockerDesktopLinuxEngine` — ENOENT).
- Postgres: **not installed** (`psql` not on PATH).

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
  `NOT_IMPLEMENTED` rather than pretending. See Step B for why `zap` is still in
  this list.
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
- Approval tokens bind to tool + target, **not to parameters**. For the current
  tools that is sufficient because each descriptor caps its own arguments, but
  it is the reason Step B splits ZAP into two tool ids instead of trusting a
  `mode` parameter.

---

## 5. Useful commands

```bash
npm run dev                    # server + Vite on :7799
npm run lint                   # tsc --noEmit && eslint
npm run test                   # vitest (253 tests)
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
```

### Env worth knowing
| Var | Effect |
|---|---|
| `SANDBOX_MODE` | `auto`/`docker` fail closed; `simulate` opts into labelled fake output |
| `DATABASE_URL` | set → Postgres required; unset → in-memory, and it says so |
| `API_PRINCIPALS` | `id:roles:secret` — `approver` role is required to approve |
| `ENABLE_CRITICAL_TOOLS` | CRITICAL tools stay disabled unless listed here |
| `SANDBOX_WORKSPACE_ROOT` | the only directory code scanners may read |
