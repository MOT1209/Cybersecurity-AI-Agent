-- SPDX-License-Identifier: Apache-2.0
--
-- Initial schema (§22). Applied by src/server/database/migrate.ts, which records
-- each file in schema_migrations so a migration runs at most once.
--
-- Conventions:
--   * every table carries created_at (and updated_at where rows mutate);
--   * foreign keys are declared, with ON DELETE chosen per relationship —
--     audit_logs and findings are NOT cascade-deleted with a project, because
--     destroying the evidence trail when a project is removed defeats the point
--     of having one;
--   * indexes cover the access paths the API actually uses.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  -- Roles gate what a principal may do; see src/server/security/principal.ts.
  roles         TEXT[] NOT NULL DEFAULT '{}',
  disabled      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  owner_id      TEXT REFERENCES users(id) ON DELETE SET NULL,
  target_domain TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Scope entries are rows, not a JSON blob, so they can be indexed, audited and
-- changed one at a time.
CREATE TABLE IF NOT EXISTS scopes (
  id          BIGSERIAL PRIMARY KEY,
  project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL CHECK (kind IN ('IN_SCOPE', 'OUT_OF_SCOPE')),
  entry       TEXT NOT NULL,
  entry_type  TEXT NOT NULL CHECK (entry_type IN ('domain','wildcard','ipv4','ipv6','cidr','url','lab')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (project_id, kind, entry)
);
CREATE INDEX IF NOT EXISTS scopes_project_kind_idx ON scopes (project_id, kind);

CREATE TABLE IF NOT EXISTS project_tools (
  project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  tool_id     TEXT NOT NULL,
  PRIMARY KEY (project_id, tool_id)
);

CREATE TABLE IF NOT EXISTS tasks (
  id          TEXT PRIMARY KEY,
  project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  trace_id    TEXT NOT NULL,
  user_prompt TEXT NOT NULL,
  target      TEXT NOT NULL,
  status      TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tasks_trace_idx ON tasks (trace_id);

CREATE TABLE IF NOT EXISTS agent_runs (
  run_id      TEXT PRIMARY KEY,
  agent_id    TEXT NOT NULL,
  task_id     TEXT REFERENCES tasks(id) ON DELETE SET NULL,
  project_id  TEXT NOT NULL,
  trace_id    TEXT NOT NULL,
  state       TEXT NOT NULL,
  error       TEXT,
  started_at  TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  duration_ms INTEGER
);
CREATE INDEX IF NOT EXISTS agent_runs_trace_idx ON agent_runs (trace_id);
CREATE INDEX IF NOT EXISTS agent_runs_agent_idx  ON agent_runs (agent_id, started_at DESC);

CREATE TABLE IF NOT EXISTS tool_runs (
  id           TEXT PRIMARY KEY,
  tool_id      TEXT NOT NULL,
  agent_run_id TEXT REFERENCES agent_runs(run_id) ON DELETE SET NULL,
  trace_id     TEXT NOT NULL,
  target       TEXT NOT NULL,
  status       TEXT NOT NULL,
  exit_code    INTEGER,
  sandbox_mode TEXT NOT NULL,
  -- The raw output is intentionally NOT stored; only its fingerprint, so a
  -- finding can cite verifiable provenance without persisting sensitive output.
  output_hash  TEXT,
  started_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tool_runs_trace_idx ON tool_runs (trace_id);

CREATE TABLE IF NOT EXISTS findings (
  id                  TEXT PRIMARY KEY,
  project_id          TEXT NOT NULL,
  task_id             TEXT,
  trace_id            TEXT,
  target              TEXT NOT NULL,
  asset               TEXT NOT NULL,
  discovered_by_agent TEXT NOT NULL,
  tool_used           TEXT NOT NULL,
  title               TEXT NOT NULL,
  description         TEXT NOT NULL,
  severity            TEXT NOT NULL CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  cvss_score          NUMERIC(3,1),
  cwe                 TEXT[] NOT NULL DEFAULT '{}',
  owasp_category      TEXT,
  impact              TEXT NOT NULL,
  -- A finding may only be CONFIRMED by the validation stage; the constraint
  -- keeps an unvalidated row from claiming confirmation.
  verification_status TEXT NOT NULL DEFAULT 'DETECTED'
    CHECK (verification_status IN ('DETECTED','ANALYZING','CONFIRMED','UNCONFIRMED','FALSE_POSITIVE')),
  confidence          SMALLINT NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
  validated_by_agent  TEXT,
  validated_at        TIMESTAMPTZ,
  validation_rationale TEXT,
  false_positive_indicators TEXT[] NOT NULL DEFAULT '{}',
  missing_evidence    TEXT[] NOT NULL DEFAULT '{}',
  remediation         JSONB,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT findings_confirmed_needs_validator
    CHECK (verification_status <> 'CONFIRMED' OR validated_by_agent IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS findings_project_idx  ON findings (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS findings_trace_idx    ON findings (trace_id);
CREATE INDEX IF NOT EXISTS findings_status_idx   ON findings (verification_status);

CREATE TABLE IF NOT EXISTS evidence (
  id           BIGSERIAL PRIMARY KEY,
  finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  source       TEXT NOT NULL,
  observation  TEXT NOT NULL,
  output_hash  TEXT,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS evidence_finding_idx ON evidence (finding_id);

CREATE TABLE IF NOT EXISTS approvals (
  id              TEXT PRIMARY KEY,
  project_id      TEXT NOT NULL,
  task            TEXT NOT NULL,
  target          TEXT NOT NULL,
  tool_id         TEXT NOT NULL,
  reason          TEXT NOT NULL,
  scope           TEXT NOT NULL,
  risk_level      TEXT NOT NULL,
  expected_impact TEXT NOT NULL,
  requested_by    TEXT NOT NULL,
  trace_id        TEXT,
  status          TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED','CONSUMED','EXPIRED')),
  -- Only the token's hash is stored: a leaked database must not yield usable
  -- approval tokens.
  token_hash      TEXT,
  decided_by      TEXT,
  decided_at      TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- The self-approval rule is also a database invariant, not just app logic.
  CONSTRAINT approvals_no_self_approval CHECK (decided_by IS NULL OR decided_by <> requested_by)
);
CREATE INDEX IF NOT EXISTS approvals_status_idx ON approvals (status, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS approvals_token_hash_idx ON approvals (token_hash) WHERE token_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit_logs (
  id                 TEXT PRIMARY KEY,
  trace_id           TEXT NOT NULL,
  actor              TEXT NOT NULL,
  user_id            TEXT,
  project_id         TEXT,
  task_id            TEXT,
  agent_id           TEXT,
  tool_id            TEXT,
  action             TEXT NOT NULL,
  target             TEXT NOT NULL,
  scope_decision     TEXT,
  permission_decision TEXT,
  risk_level         TEXT,
  approval_id        TEXT,
  status             TEXT NOT NULL,
  details            TEXT NOT NULL,
  ip_address         TEXT,
  output_hash        TEXT,
  -- Tamper-evidence: each row chains to the previous row's hash, so removing or
  -- editing a record breaks the chain for everything after it.
  prev_hash          TEXT,
  entry_hash         TEXT NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_logs_created_idx ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_trace_idx   ON audit_logs (trace_id);

CREATE TABLE IF NOT EXISTS labs (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  image       TEXT NOT NULL,
  network     TEXT NOT NULL,
  status      TEXT NOT NULL,
  container_id TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS knowledge_documents (
  id          TEXT PRIMARY KEY,
  source      TEXT NOT NULL,
  source_url  TEXT,
  title       TEXT NOT NULL,
  content     TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_messages (
  id            BIGSERIAL PRIMARY KEY,
  trace_id      TEXT NOT NULL,
  from_agent    TEXT NOT NULL,
  to_agent      TEXT NOT NULL,
  message_type  TEXT NOT NULL,
  payload       JSONB NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_messages_trace_idx ON agent_messages (trace_id);
