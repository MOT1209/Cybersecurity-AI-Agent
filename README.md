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

Currently registered: **`recon`** (real, sandboxed nmap). The other eleven
agents are catalog entries in the UI and are **not** executable.

### Tool registry
`src/server/tools/registry.ts` distinguishes three states, and never conflates
them:

| State | Behavior |
|---|---|
| Registered **and** implemented (`nmap`) | executes for real |
| Registered, no adapter (`nuclei`, `zap`, `semgrep`, `trivy`, `subfinder`, `prowler`, `volatility`) | `503 NOT_AVAILABLE` with the reason |
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
- Template and model-generated findings carry `hypothetical: true` with
  `retestStatus: "UNVERIFIED"` and confidence `0`. Only findings produced by a
  real tool run are presented as observed.

> ⚠️ **State is in-memory.** Projects, audit logs and circuit breakers reset on
> every restart and are not shared across instances. Do not run more than one
> replica until a persistent store is added.
