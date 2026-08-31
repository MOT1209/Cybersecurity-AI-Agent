import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import path from "path";

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.SANDBOX_MODE = "simulate";
  process.env.AI_PROVIDER = "local";
});

import { MemoryDatabase } from "../src/server/database/memory";
import { PostgresDatabase } from "../src/server/database/postgres";
import type { PgPool } from "../src/server/database/postgres";
import { runMigrations, listMigrationFiles } from "../src/server/database/migrate";
import { initDatabase, getDatabase, resetDatabase, databaseStatus } from "../src/server/database/index";
import { addAuditLog, auditLogsStore, verifyAuditChain } from "../src/server/core/store";
import { fromNmapPorts } from "../src/server/findings/engine";
import { parsePrincipals, resolvePrincipal, hasRole, SHARED_KEY_PRINCIPAL, ANONYMOUS_PRINCIPAL, resetPrincipals } from "../src/server/security/principal";

const MIGRATIONS = path.join(process.cwd(), "src", "server", "database", "migrations");

/** Minimal fake pool: records statements and replays canned rows. */
function fakePool(rowsFor: (sql: string) => Record<string, unknown>[] = () => []) {
  const statements: { sql: string; values?: unknown[] }[] = [];
  const pool: PgPool = {
    async query(sql, values) {
      statements.push({ sql, values });
      return { rows: rowsFor(sql) };
    },
    async end() {},
  };
  return { pool, statements };
}

describe("memory database", () => {
  it("round-trips findings and applies a validation update", async () => {
    const db = new MemoryDatabase();
    const f = fromNmapPorts([{ port: 22, protocol: "tcp", state: "open", service: "ssh" }], {
      projectId: "p1", target: "192.168.1.50", agentId: "recon", toolId: "nmap", traceId: "t1",
    });
    await db.findings.insertMany(f);
    expect(await db.findings.list({ traceId: "t1" })).toHaveLength(1);
    expect((await db.findings.get(f[0].id))?.validation.status).toBe("DETECTED");

    await db.findings.updateValidation(f[0].id, {
      status: "CONFIRMED", confidence: 90, validatedByAgent: "validation",
      falsePositiveIndicators: [], missingEvidence: [],
    });
    expect((await db.findings.get(f[0].id))?.validation.status).toBe("CONFIRMED");
    expect(await db.findings.list({ status: "DETECTED" })).toHaveLength(0);
  });

  it("reports itself as non-persistent so the caller is not misled", async () => {
    await resetDatabase();
    delete process.env.DATABASE_URL;
    await initDatabase();
    const status = await databaseStatus();
    expect(status.kind).toBe("memory");
    expect(status.persistent).toBe(false);
    expect(status.note).toMatch(/lost on restart/);
  });
});

describe("database resolver fails closed", () => {
  afterEach(async () => {
    delete process.env.DATABASE_URL;
    await resetDatabase();
  });

  it("uses memory when DATABASE_URL is unset", async () => {
    await resetDatabase();
    delete process.env.DATABASE_URL;
    expect((await initDatabase()).kind).toBe("memory");
  });

  it("refuses to start silently in memory when DATABASE_URL is unreachable", async () => {
    await resetDatabase();
    // Port 1 is reserved and never listening.
    process.env.DATABASE_URL = "postgres://u:p@127.0.0.1:1/nope";
    process.env.DATABASE_SSL = "false";
    process.env.DATABASE_CONNECT_TIMEOUT_MS = "500";
    await expect(initDatabase()).rejects.toThrow(/unreachable|Refusing to start/i);
    // Nothing was cached, so a later successful init is still possible.
    await resetDatabase();
    delete process.env.DATABASE_URL;
    expect(getDatabase().kind).toBe("memory");
  }, 20000);
});

describe("migrations", () => {
  it("ships at least one migration and applies them in lexical order", async () => {
    const files = await listMigrationFiles(MIGRATIONS);
    expect(files.length).toBeGreaterThan(0);
    expect([...files].sort()).toEqual(files);
  });

  it("records each migration and runs it inside a transaction", async () => {
    const { pool, statements } = fakePool();
    const res = await runMigrations(pool, MIGRATIONS);
    expect(res.applied).toContain("001_init.sql");
    const sqls = statements.map((s) => s.sql.trim());
    expect(sqls.some((s) => s.startsWith("BEGIN"))).toBe(true);
    expect(sqls.some((s) => s.startsWith("COMMIT"))).toBe(true);
    expect(sqls.some((s) => s.includes("INSERT INTO schema_migrations"))).toBe(true);
  });

  it("skips a migration already recorded with a matching checksum", async () => {
    const { pool: probe } = fakePool();
    await runMigrations(probe, MIGRATIONS);
    // Replay with the real checksum recorded.
    const fs = await import("fs/promises");
    const crypto = await import("crypto");
    const sql = await fs.readFile(path.join(MIGRATIONS, "001_init.sql"), "utf8");
    const checksum = crypto.createHash("sha256").update(sql).digest("hex");

    const { pool } = fakePool((s) =>
      s.includes("SELECT name, checksum") ? [{ name: "001_init.sql", checksum }] : [],
    );
    const res = await runMigrations(pool, MIGRATIONS);
    expect(res.applied).toHaveLength(0);
    expect(res.skipped).toContain("001_init.sql");
  });

  it("refuses to proceed when an applied migration was edited on disk", async () => {
    const { pool } = fakePool((s) =>
      s.includes("SELECT name, checksum")
        ? [{ name: "001_init.sql", checksum: "0".repeat(64) }]
        : [],
    );
    await expect(runMigrations(pool, MIGRATIONS)).rejects.toThrow(/modified after it was applied/);
  });

  it("rolls back and reports the file when a migration fails", async () => {
    let failed = false;
    const pool: PgPool = {
      async query(sql) {
        if (sql.includes("CREATE TABLE IF NOT EXISTS users")) {
          failed = true;
          throw new Error("syntax error");
        }
        return { rows: [] };
      },
      async end() {},
    };
    await expect(runMigrations(pool, MIGRATIONS)).rejects.toThrow(/rolled back/);
    expect(failed).toBe(true);
  });
});

describe("postgres repositories", () => {
  it("parameterizes every finding query instead of interpolating input", async () => {
    const { pool, statements } = fakePool();
    const db = new PostgresDatabase(pool);
    await db.findings.list({ projectId: "p'; DROP TABLE findings;--", traceId: "t1" });
    const q = statements.find((s) => s.sql.includes("FROM findings"))!;
    expect(q.sql).not.toContain("DROP TABLE");
    expect(q.values).toContain("p'; DROP TABLE findings;--");
    expect(q.sql).toMatch(/project_id = \$1/);
    expect(q.sql).toMatch(/trace_id = \$2/);
  });

  it("clamps the list limit rather than trusting the caller", async () => {
    const { pool, statements } = fakePool();
    const db = new PostgresDatabase(pool);
    await db.findings.list({ limit: 999999 });
    const q = statements.find((s) => s.sql.includes("FROM findings"))!;
    expect(q.values![q.values!.length - 1]).toBe(1000);
  });

  it("writes audit entries with their hash chain and never the raw output", async () => {
    const { pool, statements } = fakePool();
    const db = new PostgresDatabase(pool);
    const entry = addAuditLog("tester", "RUN_NMAP", "192.168.1.50", "COMPLETED", "d", "SECRET-OUTPUT");
    await db.audit.append(entry);
    const q = statements.find((s) => s.sql.includes("INSERT INTO audit_logs"))!;
    expect(q.values).toContain(entry.entryHash);
    expect(JSON.stringify(q.values)).not.toContain("SECRET-OUTPUT");
    expect(JSON.stringify(q.values)).toContain("sha256:");
  });

  it("exposes no update or delete path on the audit repository", () => {
    const { pool } = fakePool();
    const audit = new PostgresDatabase(pool).audit as unknown as Record<string, unknown>;
    expect(audit.update).toBeUndefined();
    expect(audit.delete).toBeUndefined();
  });
});

describe("audit hash chain", () => {
  it("chains each entry to its predecessor", () => {
    const a = addAuditLog("t", "A", "x", "OK", "1");
    const b = addAuditLog("t", "B", "x", "OK", "2");
    expect(b.prevHash).toBe(a.entryHash);
    expect(verifyAuditChain().intact).toBe(true);
  });

  it("detects a silently edited record", () => {
    addAuditLog("t", "C", "x", "OK", "3");
    const target = auditLogsStore[0];
    const original = target.details;
    target.details = "tampered";
    const result = verifyAuditChain();
    expect(result.intact).toBe(false);
    expect(result.brokenAt).toBe(target.id);
    target.details = original; // restore for later tests
    expect(verifyAuditChain().intact).toBe(true);
  });

  it("gives every entry a unique id even within the same millisecond", () => {
    const ids = new Set(Array.from({ length: 50 }, () => addAuditLog("t", "D", "x", "OK", "n").id));
    expect(ids.size).toBe(50);
  });
});

describe("principals and roles", () => {
  beforeEach(() => resetPrincipals());

  it("parses id:roles:secret entries", () => {
    const p = parsePrincipals("alice:admin|approver:s1,bot:operator:s2");
    expect(p.map((x) => x.id)).toEqual(["alice", "bot"]);
    expect(p[0].roles).toEqual(["admin", "approver"]);
  });

  it("drops malformed or role-less entries instead of defaulting them open", () => {
    expect(parsePrincipals("noroles::secret")).toHaveLength(0);
    expect(parsePrincipals("only:two")).toHaveLength(0);
    expect(parsePrincipals("bad:notarole:secret")).toHaveLength(0);
    expect(parsePrincipals("")).toHaveLength(0);
  });

  it("never stores the raw secret on the parsed principal", () => {
    const p = parsePrincipals("alice:admin:supersecret");
    expect(JSON.stringify(p)).not.toContain("supersecret");
  });

  it("resolves a key to its principal and rejects a wrong one", () => {
    process.env.API_PRINCIPALS = "alice:approver:s1,bot:operator:s2";
    resetPrincipals();
    expect(resolvePrincipal("s1")?.id).toBe("alice");
    expect(resolvePrincipal("s2")?.id).toBe("bot");
    expect(resolvePrincipal("nope")).toBeNull();
    expect(resolvePrincipal(undefined)).toBeNull();
    delete process.env.API_PRINCIPALS;
    resetPrincipals();
  });

  it("treats admin as implying every role", () => {
    expect(hasRole({ id: "a", roles: ["admin"] }, "approver")).toBe(true);
    expect(hasRole({ id: "b", roles: ["operator"] }, "approver")).toBe(false);
    expect(hasRole(null, "viewer")).toBe(false);
  });

  it("denies the approver role to the shared key and to anonymous dev", () => {
    // A shared key is not a person, so it must not satisfy human approval.
    expect(hasRole(SHARED_KEY_PRINCIPAL, "approver")).toBe(false);
    expect(hasRole(ANONYMOUS_PRINCIPAL, "approver")).toBe(false);
    expect(hasRole(SHARED_KEY_PRINCIPAL, "operator")).toBe(true);
  });
});
