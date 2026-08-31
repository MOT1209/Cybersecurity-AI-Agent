/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Database resolver.
 *
 * Fail-closed, matching the sandbox's contract: if `DATABASE_URL` is set, the
 * platform is being told persistence matters, so an unreachable server is a
 * startup ERROR — not a quiet downgrade to memory. Losing findings and audit
 * records because a connection string had a typo is exactly the kind of silent
 * degradation this platform refuses everywhere else.
 *
 * With no `DATABASE_URL`, the in-memory backend is used and says so plainly.
 */

import { MemoryDatabase } from "./memory";
import { PostgresDatabase, createPool } from "./postgres";
import { runMigrations } from "./migrate";
import type { Database } from "./types";
import { registerAuditSink } from "../core/store";

export * from "./types";
export { MemoryDatabase } from "./memory";
export { PostgresDatabase } from "./postgres";
export { runMigrations, listMigrationFiles } from "./migrate";

let instance: Database | null = null;
let initError: string | null = null;

export interface InitOptions {
  /** Run pending migrations after connecting. Default true for Postgres. */
  migrate?: boolean;
}

/**
 * Resolve the backend once per process. Throws when `DATABASE_URL` is set but
 * the server cannot be reached or migrated.
 */
export async function initDatabase(opts: InitOptions = {}): Promise<Database> {
  if (instance) return instance;

  const url = process.env.DATABASE_URL?.trim();
  if (!url) {
    instance = new MemoryDatabase();
    return instance;
  }

  let pool;
  try {
    pool = await createPool(url);
  } catch (err) {
    initError = `Postgres driver could not be loaded: ${(err as Error).message}`;
    throw new Error(initError);
  }

  const db = new PostgresDatabase(pool);
  if (!(await db.healthy())) {
    initError =
      "DATABASE_URL is set but the Postgres server is unreachable. " +
      "Refusing to start with silent in-memory persistence — fix the connection, " +
      "or unset DATABASE_URL to run explicitly in memory.";
    await db.close().catch(() => {});
    throw new Error(initError);
  }

  if (opts.migrate !== false) {
    await runMigrations(pool);
  }

  // Audit entries are written through to Postgres from here on.
  registerAuditSink((entry) => db.audit.append(entry));

  instance = db;
  return instance;
}

/** The active database. Falls back to memory only when init was never called. */
export function getDatabase(): Database {
  if (!instance) instance = new MemoryDatabase();
  return instance;
}

/** Non-sensitive status for /api/health. Never includes the connection string. */
export async function databaseStatus(): Promise<{
  kind: string;
  healthy: boolean;
  persistent: boolean;
  note?: string;
}> {
  const db = getDatabase();
  const healthy = await db.healthy();
  return {
    kind: db.kind,
    healthy,
    persistent: db.kind === "postgres",
    note:
      db.kind === "memory"
        ? "In-memory backend: findings, runs and audit records are lost on restart and are not shared across replicas."
        : initError ?? undefined,
  };
}

/** Test helper: drop the resolved instance so the next init re-resolves. */
export async function resetDatabase(): Promise<void> {
  if (instance) await instance.close().catch(() => {});
  instance = null;
  initError = null;
}
