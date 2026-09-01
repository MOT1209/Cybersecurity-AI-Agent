# 🛡️ CYBERGUARD AI — Multi-Agent Cybersecurity Platform

CYBERGUARD AI is a modular, multi-agent cybersecurity assessment, analysis, and remediation platform with strict authorization boundaries, automated error recovery, and robust backend infrastructure.

---

## 🔒 Security & Deployment

### 1. API Key Authentication (`APP_ACCESS_KEY`)
All `/api/*` endpoints (except `/api/health`) are guarded with the `x-api-key` header verification middleware.
- **Environment Variable:** `APP_ACCESS_KEY`
- **Header Required:** `x-api-key: <your_key_here>`
- **Behavior:**
  - If `APP_ACCESS_KEY` is configured in `.env`, incoming requests without a matching `x-api-key` header receive `401 Unauthorized`.
  - In local development where `APP_ACCESS_KEY` is omitted, open access is allowed for development ease.
- **Frontend requirement:** the SPA sends the header via the shared `src/lib/api.ts` client, which reads it from the build-time env var **`VITE_APP_ACCESS_KEY`**. If you set `APP_ACCESS_KEY` you **must** set `VITE_APP_ACCESS_KEY` to the same value or the whole UI will get 401s. Because this value is embedded in the client bundle, treat it as a coarse gate (rate-limit / bot filter), not a real trust boundary — put a proper auth proxy in front for real deployments.

### Model configuration (`GEMINI_MODEL`)
All AI calls use `GEMINI_MODEL` (default `gemini-2.5-flash`). It must be a real, currently-served model id — an invalid id makes every live call fail and silently fall back to the deterministic local engine. Some helper endpoints (`/api/gemini/simulate-cmd`, `/generate-report`, `/explain-threat`) are template-only by design and never call the model.

### 2. Rate Limiting Architecture (`express-rate-limit`)
To prevent Denial of Service (DoS) and excessive API token consumption, multi-tiered IP-based rate limiters are enforced:
- **Global API Rate Limiter:**
  - **Scope:** All `/api/*` endpoints
  - **Limit:** 60 requests per 15-minute window per client IP
  - **Response (429):** Returns remaining retry seconds in JSON format.
- **AI & Orchestration Strict Rate Limiter:**
  - **Scope:** `/api/gemini/*` and `/api/orchestrator/run-mission`
  - **Limit:** 15 requests per 15-minute window per client IP
  - **Response (429):** Protects paid Gemini API quota with strict limits and clear retry guidance.

### 3. Input Validation & Prompt Injection Defense
- **Type & Length Bounds:** Enforces strict string types, non-emptiness, and character limits (e.g., max 4,000 characters for prompts/code, max 500 characters for targets/identifiers).
- **Prompt Isolation Boundary:** All untrusted user inputs fed to LLM reasoning pipelines are encapsulated inside `<user_input>...</user_input>` delimiters, with explicit system instructions instructing the models to process enclosed text purely as data.

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18+ (or Bun — the repo is locked with `bun.lock`)

### Environment Setup
Create a `.env` file from `.env.example`:
```bash
cp .env.example .env
```

Configure your environment variables:
```env
GEMINI_API_KEY=your_gemini_api_key_here
APP_ACCESS_KEY=your_secure_api_key_here
```

### Running Locally
```bash
npm install
npm run dev
```
The server will boot on `http://0.0.0.0:7799`.

### Tests & Typecheck
```bash
npm run lint   # tsc --noEmit
npm run test   # vitest (backend smoke + auth/gateway/validation)
```

### Production Build
```bash
npm run build
npm run start
```

---

## 🤖 Agent runtime & the honest-failure contract

### Agent Manager
Agents are registered with `AgentManager` (`src/server/agents/manager.ts`) and
dispatched by id — the orchestrator never imports a concrete agent. Each agent
publishes an `AgentDescriptor` (capabilities, skills, `allowedTools`,
permissions, risk level, timeout, I/O schemas, memory policy). Registration is
rejected if an agent's `allowedTools` names a tool missing from the tool
registry, so a broken allowlist fails at startup rather than widening at
execution time. Dispatch enforces the declared timeout, supports cancellation
via `AbortSignal`, and records every run.

Currently registered and executable:

| Agent | Tools | Notes |
|---|---|---|
| `recon` | nmap | sandboxed TCP connect scan |
| `web_security` | nuclei | non-intrusive templates; detections stay unconfirmed |
| `code_security` | semgrep, trivy | read-only workspace mount, no network |
| `validation` | *(none)* | evidence review only — no exploitation |

The other nine agents are catalog entries in the UI and are **not** executable;
`/api/agents` lists only the three above.

The orchestrator chains on **evidence, not on the prompt**: the web scan runs
only when recon actually observed an open HTTP port. When it does not, the step
is returned `SKIPPED` with the reason, and a web-scan failure never discards the
real recon result.

### Tool registry
`src/server/tools/registry.ts` distinguishes three states, and never conflates
them:

| State | Behavior |
|---|---|
| Registered **and** implemented (`nmap`, `subfinder`, `nuclei`, `semgrep`, `trivy`) | executes for real |
| Registered, no adapter (`zap`, `prowler`, `volatility`) | `503 NOT_AVAILABLE` with the reason |
| Not registered | `400 TOOL_NOT_REGISTERED` — fail closed |

### Honest failure (no fabricated results)
The platform will not report a success that did not happen.

- With `SANDBOX_MODE=auto`/`docker` and no reachable Docker daemon, tool
  execution raises `NOT_AVAILABLE` (HTTP 503) carrying the real reason. It does
  **not** fall back to the simulator.
- Simulation requires an explicit `SANDBOX_MODE=simulate`, and its output is
  prefixed `SIMULATED — NOT A REAL RESULT`.
- Orchestrator steps for which no agent/tool exists are returned as `PENDING`,
  not `COMPLETED`.
- The error-recovery engine **classifies** a failure and **recommends** a
  strategy. It does not retry, so it reports `RECOVERY_PROPOSED` with
  `recoveryExecuted: false` — never `AUTO_RECOVERED`. Recovery history starts
  empty; it no longer ships with fabricated incidents.
- `/api/gemini/simulate-cmd` explains a command and returns `executed: false`.
  It previously returned a hardcoded nmap report — invented ports and versions —
  for any target.
- Template and model-generated findings carry `hypothetical: true` with
  `retestStatus: "UNVERIFIED"` and confidence `0`. Only findings produced by a
  real tool run are presented as observed.

### Findings & validation
A scanner result is **not** a vulnerability. Every detection enters the findings
engine at `DETECTED` with confidence `0`, and there is no code path in the engine
that produces a `CONFIRMED` finding — only the Validation agent can move one.

The Validation agent performs **no exploitation**. It reviews the evidence that
already exists:

- **Scope** — a finding about an asset outside the approved scope is never
  confirmed, however good the evidence looks.
- **Traceability** — evidence without a sha256 linking it to a recorded tool run
  is capped at confidence 40 and cannot be confirmed.
- **Directness** — only direct observations (`nmap`, `subfinder`) can reach
  `CONFIRMED`. Inferential tools (`nuclei`, `semgrep`, `trivy`) stay
  `UNCONFIRMED` pending safe reproduction, with their false-positive risks and
  missing evidence spelled out.

The deterministic rules set the ceiling. The model may only **lower** confidence
and add false-positive reasoning — its "penalty" is clamped non-negative, so it
cannot talk a finding into being real.

Browse results at `GET /api/findings` (filter by `status`, `traceId`,
`minSeverity`) and `GET /api/findings/:id`.

### Sandbox isolation
Every containerized tool run gets:

- a **dedicated internal bridge network** (`SANDBOX_NETWORK_NAME`), never the
  host's shared default bridge. The network is `internal` unless
  `SANDBOX_ALLOW_EGRESS=true`, so a scanner cannot route off the lab;
- **no network at all** for offline tools (`semgrep`, `trivy`, `volatility`);
- a **read-only root filesystem** with a single `tmpfs` scratch mount at
  `/tmp/cyberguard` (`noexec,nosuid,64m`) that dies with the container;
- **all Linux capabilities dropped**, `no-new-privileges`, non-privileged,
  private IPC, no bind mounts and **no host Docker socket**;
- CPU / memory (with no swap headroom) / pid ceilings and a wall-clock timeout
  taken from the tool's own descriptor — a caller cannot widen them.

### Code-scanning tools and the workspace boundary
`semgrep` and `trivy` are **filesystem-scoped**: their target is a path, not a
host, so the network allow-list does not apply to them. Containment does.

- Only paths whose **real path** (symlinks resolved) sits inside
  `SANDBOX_WORKSPACE_ROOT` are mountable — `../`, an absolute path and a symlink
  pointing out of the tree are all rejected, and the root itself cannot be
  mounted.
- The mount is **read-only**, and it is the only bind mount the sandbox ever
  makes.
- Both tools run with **no network** and fully offline (`--metrics=off`,
  `--offline-scan`, `--skip-db-update`), so an untrusted repository cannot be
  modified and cannot phone home.
- Semgrep rulesets come from a curated allowlist; a free-form `--config` would
  accept a URL, which is caller-driven remote rule execution.
- Trivy deliberately does **not** expose remote `image` scanning as a mode flag
   — that needs registry egress and a caller-controlled image reference, which
  is a different trust boundary.

### Risk policy & human approval
Risk is read from the tool registry — never from a name list, a request body, or
a model. `src/server/security/policy.ts` maps it to what the platform will do:

| Risk | Policy |
|---|---|
| LOW / MEDIUM | may run automatically; sandboxed and fully logged |
| HIGH | explicit human approval required |
| CRITICAL | disabled by default, lab/private targets only, and only when listed in `ENABLE_CRITICAL_TOOLS` |

An unregistered tool is treated as CRITICAL, so the most restrictive policy
applies to anything unknown.

**A caller cannot approve its own request.** There is no `approved: true` flag.
Instead:

1. `POST /api/tools/execute` on a gated tool returns `428` **and opens a real
   approval request**, returning its `approvalId`.
2. A human calls `POST /api/approvals/:id/decision` with
   `{ "decision": "APPROVED", "decidedBy": "<operator>" }`. `decidedBy` must
   differ from the requester, or the API answers `409`.
3. The response carries a single-use `approvalToken`, bound to that exact
   tool + target and burned on redemption.
4. `POST /api/tools/execute` with that `approvalToken` runs once.

The gateway also enforces the project's `allowedTools` list, which V1 declared
but never checked, and returns an ordered `checks[]` record of every decision it
made.

---

## 🧪 Lab targets

Deliberately vulnerable applications (Juice Shop, DVWA, WebGoat) can be started
as scan targets from a **fixed catalog**: `POST /api/labs/:id/start` takes a
catalog id, never an image reference — accepting one would be remote code
execution by API.

| Rule | Why |
|---|---|
| No published host ports, ever | a vulnerable app reachable from the host is an incident, not a lab |
| Internal sandbox network only | agents reach it at `http://<name>.lab:<port>`; nothing else can |
| Unprivileged, no bind mounts, capped memory and pids | the target is hostile by design |
| Status is read from `docker inspect` | a lab whose container is gone reports `STOPPED`, never `RUNNING` by assumption |

With no Docker daemon, `/api/labs` still answers — every lab reads `STOPPED`
with the real reason, and a start attempt returns `503 NOT_AVAILABLE` rather
than pretending.

---

## 🖥️ What the UI shows

The dashboard reflects backend truth rather than a static catalog:

| Page | Source | What it will not do |
|---|---|---|
| **Tool Registry** | `GET /api/tools/health` | show a tool as usable without a verified adapter, reachable sandbox and present image; `imagePresent: null` renders as "not checked", never as "no" |
| **Findings** | `GET /api/findings` | present severity as a verdict — severity is the tool's claim, verification status is the platform's, and the validator's rationale, false-positive risks and missing evidence are shown |
| **Approvals** | `GET /api/approvals` | send a `decidedBy` (the server uses the authenticated principal) or re-show a granted token, which is displayed once and burned on use |
| **Agents mesh** | `GET /api/agents` | render the twelve-agent catalog as live — each card is labelled `EXECUTABLE` or `NOT IMPLEMENTED` |
| **Error Recovery** | `GET /api/error-recovery/events` | claim a retry happened — it is labelled `DIAGNOSIS ONLY` and reports `RECOVERY_PROPOSED` |
| **Lab Targets** | `GET /api/labs` | offer a host URL for a vulnerable app — only the sandbox-internal address is shown, and every status is read from Docker (a lab whose container is gone reads `STOPPED`) |

---

## 🗄️ Persistence, identity and the audit chain

### Backends
| `DATABASE_URL` | Behavior |
|---|---|
| unset | in-memory backend; `/api/database/status` reports `persistent: false` and says data is lost on restart |
| set and reachable | Postgres; migrations run at startup |
| set and **unreachable** | **startup fails** — it will not quietly downgrade to memory and lose findings and audit records |

Findings and audit entries are written through to the configured backend. The
write is not awaited (a slow database must not stall a scan) but a failure is
logged loudly rather than swallowed.

### Migrations
`src/server/database/migrations/*.sql`, applied in lexical order inside a
transaction and recorded in `schema_migrations` with a checksum. Editing a
migration that has already been applied is a hard error — add a new one instead.
The schema enforces security invariants at the database level too: a finding
cannot be `CONFIRMED` without a validator, and an approval cannot be decided by
its own requester.

### Identities and roles
`API_PRINCIPALS` maps each API key to an identity and a role set
(`admin | operator | approver | viewer`; `admin` implies all), compared in
constant time against a stored sha256.

**Approving a high-risk tool requires the `approver` role, and the decider is
the authenticated principal — not a name supplied in the request body.** The
legacy shared `APP_ACCESS_KEY` grants `operator`/`viewer` but deliberately
**not** `approver`: a key everyone holds is not a person, so it cannot satisfy a
human-approval requirement.

### Tamper-evident audit log
Each audit entry commits to its predecessor's hash. `verifyAuditChain()`
recomputes the chain and reports the first broken link, so a quietly edited or
deleted record is detectable. This is tamper-**evidence**, not tamper-proofing:
someone with write access to the entire store could recompute the chain. It
raises the cost of a silent edit from trivial to total.

> ⚠️ **Without `DATABASE_URL`, state is in-memory.** Projects, circuit breakers
> and recovery history reset on every restart and are not shared across
> instances. Do not run more than one replica until Postgres is configured.
