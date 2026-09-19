# CYBERGUARD AI — Current-State Architecture

**Status:** Phase 0 deliverable (repository inspection). Reflects branch `main` at
commit `324fe95`. Baseline before this inspection: `npm run lint` — 0 errors,
51 pre-existing `no-explicit-any` warnings; `npm run test` — **349/349 passing**
across 27 files.

This document describes what **actually runs today**, backed by file:line
citations. It intentionally does not describe the target architecture from the
master prompt — see that prompt's own §2 for the target shape. Where this repo
diverges from the target, that gap is the roadmap, not a defect to silently
paper over.

Per `docs/README.md:3-5`, everything else under `docs/` (the two Architecture
Review docs, the Technical Review doc, `roadmap-report.html`) predates the
"V2" rewrite and is explicitly marked stale by the project itself. This file
and `plan.md` are the only current sources of truth on top of the code.

---

## 1. Entry point & HTTP layer

`server.ts` (43 lines) is a thin process entrypoint only: it resolves
persistence via `initDatabase()` before binding (`server.ts:21`), warns loudly
if running in-memory (`server.ts:22-27`), and re-exports `createApp` from
`src/server/http/app.ts` for the test suite. All routing lives in
`src/server/http/`.

`app.ts` (`createApp()`, lines 35-93) wires, in order: helmet with CSP
disabled outside production (44-48), a 1MB JSON body limit (52), the global
rate limiter + monthly budget guard + daily per-IP exec cap + API-key auth
middleware on `/api` (55-58), a stricter limiter on Gemini/orchestrator routes
(61-62), then 8 route groups (65-72):

| Route file | Endpoints |
|---|---|
| `infra.ts` | `/api/health` (public), `/api/database/status`, `/api/projects`, `/api/runtime/mode` |
| `security.ts` | `/api/gateway/check`, `/api/approvals`, `/api/approvals/:id/decision` |
| `orchestrator.ts` | mission execution + error-recovery |
| `labs.ts` | list/get/start/stop lab containers |
| `knowledge.ts` | knowledge search, findings listing |
| `tools.ts` | tool registry listing, health, `/api/tools/execute` |
| `introspection.ts` | agents, runs, catalog, events, logs |
| `gemini.ts` | chat, code audit, and three template-only helper endpoints |

`middleware.ts` resolves the request principal (API_PRINCIPALS →
APP_ACCESS_KEY → anonymous-viewer, lines 139-171) and exposes
`requireRole`/`callerHasRole` (173-196).

## 2. Agent system

Files: `src/server/agents/{base,index,manager,types}.ts`,
`catalog/{catalog,index,types}.ts`, and one folder per runtime agent.

**Only 7 of 50 catalog-declared agents are actually registered and
executable**: `recon`, `web_security`, `code_security`, `validation`,
`remediation`, `reporting`, `testing` (`agents/index.ts:37-43`). The other 43
are `CATALOG_ONLY` by construction.

The catalog (`catalog/catalog.ts`, 50 entries, ordinals validated contiguous
1-50 at `catalog/index.ts:95-101`) computes each entry's status **live**, not
as a hand-maintained label (`catalog/index.ts:116-158`):

- `CATALOG_ONLY` — no registered runtime agent for this id.
- `PARTIAL` — agent registered, but ≥1 required tool has no real adapter.
- `IMPLEMENTED` — agent registered and every required tool is a real adapter.

Under current registrations: **7 IMPLEMENTED, 0 PARTIAL, 43 CATALOG_ONLY.**
This isn't an accident of good luck — the manifest's declared `requiredTools`
per agent are overlaid by each live agent's actual `allowedTools`
(`code/agent.ts:96`, `web/agent.ts:80`, etc.), so an agent that only ever
touches tools with real adapters cannot land in `PARTIAL` under this scheme.
Worth flagging as a modeling gap: `PARTIAL` is reachable only if a *live*
agent's own `allowedTools` names a declared-only tool — the manifest's
aspirational tool list is cosmetic once an agent is registered.

`AgentManager` (`manager.ts`) enforces that `register()` rejects an agent
naming an unregistered tool (47-56), runs `dispatch()` under a timeout race
(100-171), and keeps a capped run history (200 entries, 121-122).

## 3. Skill platform

**Update (post-Phase-0):** a real, minimal Skill Platform now exists under
`src/server/skills/`: `manifest.ts` (zod schema for on-disk `skill.json`),
`loader.ts` (discovers `<root>/<id>/skill.json` + `SKILL.md`, validates,
never coerces a bad package into looking valid), `scanner.ts` (six
deterministic security checks — required tools are real adapters, no MCP
dependency since none exists, permissions on a fixed allowlist, dependencies
resolve, CRITICAL disabled by default, `securityPolicy.maxRiskLevel`
consistent with the skill's own risk), and `registry.ts` (ties discovery +
scanning together, computing `isSkillExecutable()` live — same honesty
pattern as the tool registry and agent catalog). Two real packages exist
(`nmap-recon`, `sast-review`), both wired to already-real tool adapters and
both `executable: true`. A read-only `/api/skills` + `/api/skills/:id` route
exposes this. Verified end-to-end against the actual production build
(`npm run build && node dist/server.cjs`), not just `tsx` dev mode.

**What this explicitly does NOT do**: nothing dispatches a skill. No agent
or orchestrator step selects or invokes a skill by id — "registered and
would be runnable" is not the same as "something runs it." That dispatch
layer, plus reconciling the catalog's pre-existing `skills: string[]` field
(which currently reuses tool ids as skill ids, e.g. `catalog.ts:36`) with
this platform's real skill ids, is real remaining work.

## 4. MCP platform

**Absent.** Zero occurrences of "mcp" (case-insensitive) anywhere under
`src/server`. The backend has no MCP registry, server manager, or discovery —
this is a from-scratch build, not a hardening pass.

## 5. Tool platform

`src/server/tools/registry.ts` runs a strict two-tier model (8-13): the
`ADAPTERS` array is real and executable; the `DECLARED` array is a descriptor
with no adapter, and running it raises `ToolNotAvailableError` rather than
faking success.

**12 real adapters**, with risk/target classification from each file:

| Tool | Risk | Target |
|---|---|---|
| subfinder, semgrep, trivy, volatility, theharvester, ctfr | LOW | network / filesystem (mixed — see code) |
| nmap, nuclei, wfuzz | MEDIUM | network |
| zap, sqlmap, xsstrike | HIGH | network |

**1 declared-only tool**: `prowler` (MEDIUM) — the registry comment states
plainly it's "blocked on a credential channel and a cloud-scope gateway
branch, neither of which exists yet" (`registry.ts:76-78`).

Resource ceiling defaults: 1 CPU / 512MB / 256 pids (`types.ts:22-26`), and a
tool cannot ask for more than its own descriptor allows — the caller doesn't
get to widen it (enforced in `sandbox/index.ts`, see §7).

## 6. Security gateway & policy

`validateSecurityGateway()` (`gateway.ts:44-209`) is the authorization entry
point, called from inside `executeTool()` (§7) — not something callers can
bypass by skipping a separate pre-check. Order of evaluation:

1. Resolve the tool's descriptor; an **unregistered tool defaults to
   CRITICAL risk** (56-57) — fail-closed by construction.
2. Filesystem-scoped tools take a separate branch (83-124): skip host
   allow/deny lists (meaningless for a file target), check project-tool
   permission, then risk policy, then approval requirement.
3. Network-scoped tools: explicit deny-list first (128-136, so a denied host
   is rejected even if it would otherwise look like a lab address), then
   allow-list/private-lab-host check (140-152), then project tool permission
   (154-164), then risk policy (`disabledByDefault`, `labOnly`, 166-184),
   then approval requirement.

Every branch appends to an ordered `checks[]` array and writes an audit
entry on both deny and allow.

`policy.ts` risk table (26-31): LOW/MEDIUM auto-run under sandbox; **HIGH
requires human approval**; **CRITICAL is disabled by default**, lab-only, and
only runnable via `ENABLE_CRITICAL_TOOLS`. No tool in the registry is
currently CRITICAL — HIGH (zap, sqlmap, xsstrike) is the ceiling in practice.

`approvals.ts`: `createApprovalRequest` mints a token-less PENDING request;
`decideApproval` **enforces `decidedBy !== requestedBy`** (113-115 — a
requester cannot approve their own action) and only then mints a single-use
32-byte token; `consumeApproval` burns it and rebinds it to the exact
tool+target pair (155-159). Default TTL 15 minutes.

`principal.ts`: roles are `admin | operator | approver | viewer` (line 20).
The shared `APP_ACCESS_KEY` maps to operator+viewer **but explicitly not
approver** (105-108 — "a shared key is not an identity"). No key at all →
viewer-only anonymous (117-120).

`workspace.ts` resolves symlinks via `fs.realpath` **before** the containment
check (40-87), closing the standard `../../` and symlink-escape classes.

## 7. Sandbox

`sandbox/index.ts`'s `executeTool()` (125-237) is the single real enforcement
chokepoint for every tool run, in this exact order: registered-tool check
(fail-closed) → security gateway → approval-token consumption (a boolean
`approved: true` flag is **not** accepted — a redeemed token is required) →
adapter-exists check unless simulation is explicitly opted into → executor
resolution → build a request capped by the descriptor's own limits → run →
audit log with a sha256 of raw output.

Two executors:

- **Docker (real)**: dynamically imports `dockerode`, probes the daemon with
  a cached 2s-timeout ping. Container posture: `ReadonlyRootfs`,
  `CapDrop: ["ALL"]`, `no-new-privileges`, `Privileged: false`, tmpfs-only
  `/tmp` (`rw,noexec,nosuid`), equal memory/swap (no swap headroom), hard
  wall-clock kill on timeout, container always removed in a `finally` block.
  Runs on a dedicated `cyberguard_sandbox` bridge network that is `Internal:
  true` by default (blocks all egress) unless `SANDBOX_ALLOW_EGRESS=true`.
- **LocalSim (simulation)**: no Docker; output is explicitly prefixed
  `"!! SIMULATED — NOT A REAL RESULT ..."` and `structuredData.simulated:
  true`. The platform never silently downgrades from Docker to simulation —
  that requires an explicit `SANDBOX_MODE=simulate`.

## 8. Labs / cyber range

`labs/manager.ts` uses a **fixed** 3-image catalog (Juice Shop, DVWA,
WebGoat, pinned tags) — a caller cannot supply an arbitrary image string.
**No published host ports anywhere** in `startLab` (`PublishAllPorts: false`,
no `HostConfig.PortBindings`); containers attach only to the internal sandbox
network.

Status reporting deliberately separates the raw Docker fact
(`containerRunning`, which can be `null`=unknown) from the service verdict
(`RUNNING | STOPPED | STARTING | UNKNOWN`) — daemon unreachable → `UNKNOWN`,
not a guess.

## 9. Findings & evidence

`findings/types.ts`: every `Finding` carries `Evidence[]` (source,
observation, optional sha256 `outputHash` of raw tool output, timestamp) and
a `Validation` object (status `DETECTED | ANALYZING | CONFIRMED |
UNCONFIRMED | FALSE_POSITIVE`, confidence 0-100 that "stays 0 until evidence
justifies more"). `isConfirmed()` is the only helper that treats a finding as
real, and it is `true` only when `status === "CONFIRMED"`.

`findings/engine.ts`: every tool-output normalizer enters a finding at
`pristineValidation()` — `DETECTED`, confidence 0. The module's own
documentation states "no path in this module ... produces a CONFIRMED
finding." `applyValidation()` is "the ONLY way a finding changes status," and
`attachRemediation()` is kept structurally separate so remediation guidance
can never influence verification status. This is a real, enforced
detection-vs-confirmation boundary, not a naming convention.

## 10. Knowledge base

Seeded **only** from a local static file (`src/data/cyberData.ts`: OWASP Top
10, MITRE ATT&CK tactics/techniques) at import time — "nothing here reaches
the network." There is no CWE text corpus (CWE ids are indexed for exact
lookup only, not full text), no NIST content, no live CVE feed.

Retrieval (`retriever.ts`) is a **real** BM25 implementation (not a stub),
with a minimum-score floor that drops weak matches rather than returning
noise. So: retrieval mechanics are genuine; the corpus itself is narrow
(two sources, static data file) relative to the target architecture's
OWASP/MITRE/CWE/NIST/CVE ambition.

## 11. Orchestrator

`orchestrator/index.ts`'s `runMission()` is a genuine multi-agent pipeline,
not one LLM call dressed up: recon (real nmap through the sandbox) → web
security conditionally, only if recon observed an open HTTP port (chaining
on evidence, not on a prompt) → LLM synthesis grounded in the real recon
output → validation (the only stage that can confirm a finding) →
remediation, testing (probes the platform's own controls each run),
reporting. It returns a `coverage[]` array stating explicitly what was and
wasn't performed and why.

Important nuance: **the orchestrator does not call the security gateway
directly.** Authorization is enforced per tool call, one level down, inside
`executeTool()` (§7) via each agent's dispatch. A denial on the recon step
propagates up uncaught; a failure on a later step is caught locally so one
denied/failed step doesn't erase earlier real results. The 50-agent catalog
plays no role in this dispatch path — only the 7 registered runtime agents
are ever invoked by a real mission.

## 12. LLM providers

Preference order: **zen → groq → claude → gemini → local**
(`llm/index.ts:9,44`). `AI_PROVIDER` env pins one if it's available; otherwise
auto-select; `generate()`/`generateJSON()` try every available provider in
order and only degrade to `local` after all fail — never throws for lack of a
model. `local` is explicitly documented as producing "clearly-labelled
deterministic scaffolding," never fabricated AI reasoning.

## 13. Persistence

`database/index.ts`'s `initDatabase()` has one behavior worth stating
precisely: **`DATABASE_URL` unset → in-memory, starts fine. `DATABASE_URL`
set but the server is unreachable → the process throws and refuses to
start**, with the message "Refusing to start with silent in-memory
persistence." This is fail-closed on purpose, not a bug.

`postgres.ts` is real — every query is parameterized (`$1, $2...`, no string
concatenation found anywhere in the file), TLS required by default. It
re-implements the same audit hash-chain verification as `core/store.ts`
independently, which is a duplication risk worth tracking (§ technical
debt).

## 14. Audit system

`core/store.ts`'s hash chain: each `AuditLogEntry` commits to a sha256 of a
fixed-order field tuple plus the previous entry's hash. **Precisely what
"tamper-evident" means here** (stated in the code's own comment): "this is
tamper-EVIDENCE, not tamper-proofing: an attacker with write access to the
whole store could recompute the chain. It raises the cost of a quiet edit
from trivial to total." In-memory storage is capped at 200 entries unless a
database is configured, in which case writes go through to Postgres
non-blockingly — a failed durable write is logged, not retried or escalated.

Circuit breakers exist and feed `diagnoseAndRecoverError`, but this is
diagnostic/advisory only: the generated event log explicitly states "no
retry has been executed," and `recoveryExecuted: false` is a fixed field —
this is truthful by construction, not a place where `AUTO_RECOVERED` could
be claimed without evidence.

## 15. Memory system

**Absent as a dedicated subsystem.** What exists instead: (a) each
`BaseAgent`'s bounded per-instance task memory (a handful of recent tasks,
in-process, lost on restart — not cross-session), and (b) `database/memory.ts`,
which is the in-memory *persistence backend* (an alternative to Postgres),
not an agent "memory" concept. Neither is short-term/long-term/project
memory as the target architecture describes it.

## 16. Workflow engine

**Absent as a generic engine.** "workflow" appears twice in `src/server`,
both incidental. What exists is the **fixed pipeline** hardcoded directly
into `runMission()`'s function body (§11) — a specific sequence, not a
configurable trigger→plan→step→agent→evidence→decision graph that could
express an arbitrary new assessment shape without code changes.

## 17. Frontend

16 components under `src/components/`. Every data-bearing component either
calls the real backend via `apiFetch` or (only `CtfArena.tsx`) reads a
static, intentionally-fixed CTF challenge dataset appropriate to its purpose
(a fixed challenge set is not the same failure mode as fabricated scan
results). No component was found hardcoding fake findings/scan output as if
live. `ErrorRecoveryCenter.tsx` carries a comment noting a prior version
"used to fake a retry client-side" and has since been fixed — consistent
with the P0-hardening commit history.

## 18. RBAC / principals

Roles: `admin | operator | approver | viewer`. Resolution precedence:
`API_PRINCIPALS` (per-key identities) → `APP_ACCESS_KEY` (shared secret,
operator+viewer, never approver) → anonymous (viewer-only, open dev mode,
read-only). `admin` implies every other role. State-changing routes are
role-gated: creating a project (admin), toggling runtime mode (admin),
deciding an approval (approver, with decider identity taken from the
authenticated principal — never from the request body), executing a tool
(operator), starting/stopping a lab (operator).

## 19. Test inventory

27 files, 349 tests, all passing. Coverage by subsystem is broad — adapters,
agent manager, API auth, approvals, catalog honesty, workspace containment,
audit, CTF data integrity, database fail-closed behavior, findings
validation, gateway hardening (including bypass attempts), no-fabricated-
success contract, knowledge provenance, lab status honesty, LLM provider
fallback, multi-agent chaining, orchestrator gateway-denial propagation,
pipeline agents, RBAC matrix, event bus, runtime modes, sandbox network
policy and resource limits, adversarial security tests, and UI/API contract
checks.

**Coverage gaps**, all consistent with the absences above: no tests for
`src/server/skills` (nothing to test yet), no MCP tests (nothing exists), no
workflow-engine tests (nothing exists), and no direct component-level
frontend tests — only the API contracts components depend on are checked.

## 20. Documentation state

- `README.md` accurately describes the current split architecture (auth
  precedence, LLM provider chain, rate limiting, prompt-injection defenses).
- `plan.md` is a live, dated engineering log of the P0-hardening pass, not
  marketing copy — worth noting its own test count (330) is now stale
  against the live-measured 349, since tests were added after that entry was
  written.
- `docs/README.md` explicitly disclaims the rest of `docs/` as predating the
  V2 rewrite; treat those HTML/PDF files as historical only.
- `docs/project-review-2026-09-17/` is newer and not covered by that
  staleness table — its currency wasn't verified in this pass.

## 21. Stack

`cyberagent-ai@0.1.0`, ESM. Scripts: `dev` (tsx), `build` (vite + esbuild),
`start`, `lint` (`tsc --noEmit && eslint .`), `test` (vitest). Key deps:
`@anthropic-ai/sdk`, `@google/genai`, `dockerode`, `pg`, `express`, `zod`,
`react` 19, `vite` 6. No MCP SDK, no Groq/Zen-specific SDK (both fetch-only
by design, per their own source comments) — consistent with §4's absence and
§12's provider descriptions.

---

## Summary: what's real vs. declared vs. absent

| Layer | State |
|---|---|
| Agent contracts, manager, dispatch | **Real** — 7 of 50 catalog agents implemented and executable |
| Agent catalog (50 entries) | **Real as an honesty ledger** — computes IMPLEMENTED/PARTIAL/CATALOG_ONLY live, not hand-labeled |
| Skill platform | **Real but minimal** — registry/loader/scanner exist and work; 2 real skills; nothing dispatches a skill yet |
| MCP platform | **Absent** — zero references in the backend |
| Tool registry + adapters | **Real** — 12 real adapters, 1 honestly declared-only (prowler) |
| Security gateway / risk policy | **Real** — fail-closed on unregistered tools/targets, ordered checks, audited |
| Human approval | **Real** — token-based, self-approval blocked, TTL-bound |
| Sandbox (Docker) | **Real** — dropped caps, RO rootfs, resource ceilings, isolated network |
| Sandbox (simulation) | **Real, and honestly labeled** — never confused with a live result |
| Labs | **Real** — fixed image catalog, no host ports, honest status states |
| Findings/evidence | **Real** — enforced DETECTED→CONFIRMED boundary, hashed evidence |
| Knowledge base | **Real but narrow** — genuine BM25 retrieval over a small static OWASP+MITRE corpus |
| Orchestrator | **Real** — evidence-chained multi-agent pipeline, not a single prompt |
| Workflow engine | **Absent** — the orchestrator is one fixed pipeline, not a generic engine |
| Memory system | **Absent** — only per-agent bounded task memory and a persistence backend named "memory" |
| Persistence | **Real** — Postgres path is parameterized and fail-closed on unreachability |
| Audit | **Real, explicitly tamper-evidence not tamper-proof** — hash-chained, capped in memory unless persisted |
| Frontend | **Real** — every data view is backend-driven; no fabricated findings found |
| RBAC | **Real** — 4 roles, enforced on every state-changing route found |

## Immediate technical debt worth tracking

1. **Catalog `PARTIAL` state is effectively unreachable** under current
   registrations, because live `allowedTools` overlays the manifest's
   aspirational tool list (§2). Adding a registered agent that legitimately
   depends on a declared-only tool (e.g. a future cloud-security agent
   needing `prowler`) is the first real test of this state.
2. **Audit hash-chain verification is implemented twice** (`core/store.ts`
   and `postgres.ts`) with no shared code — a fix to one will not
   automatically apply to the other (§13, §14).
3. **Durable audit/finding writes are fire-and-forget** — a failed write to
   Postgres is logged but not retried or escalated to the caller (§13, §14).
4. **Knowledge corpus is narrow relative to any "OWASP/MITRE/CWE/NIST/CVE"
   ambition** — real retrieval, thin source coverage (§10).
5. **No MCP platform, workflow engine, or memory system exist yet** — these
   remain the largest gaps against the target architecture. A minimal Skill
   Platform now exists (registry/loader/scanner, 2 real skills) but has no
   dispatch path — an agent or the orchestrator selecting and invoking a
   skill by id is still a substantial, separate build.
6. **The agent catalog's `skills: string[]` field predates the Skill
   Platform** and currently reuses tool ids as skill ids (e.g.
   `catalog.ts:36`: `skills: ["nmap", "subfinder"]`). Reconciling that field
   with real skill ids from `src/server/skills/registry.ts` is unresolved.
