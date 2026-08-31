/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Migration runner. Applies every .sql file in ./migrations in lexical order,
 * inside a transaction, recording each in schema_migrations so it runs once.
 *
 * A migration whose recorded checksum no longer matches the file on disk is a
 * hard error: silently tolerating an edited migration means two environments
 * believe they share a schema when they do not.
 */

import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { createHash } from "crypto";
import type { PgPool } from "./postgres";

function migrationsDir(): string {
  // Works under tsx (ESM) and after esbuild bundling to CJS.
  const here =
    typeof __dirname !== "undefined"
      ? __dirname
      : path.dirname(fileURLToPath(import.meta.url));
  return path.join(here, "migrations");
}

export interface MigrationResult {
  applied: string[];
  skipped: string[];
}

export async function listMigrationFiles(dir = migrationsDir()): Promise<string[]> {
  const entries = await fs.readdir(dir);
  return entries.filter((f) => f.endsWith(".sql")).sort();
}

export async function runMigrations(pool: PgPool, dir = migrationsDir()): Promise<MigrationResult> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name       TEXT PRIMARY KEY,
      checksum   TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);

  const { rows } = await pool.query(`SELECT name, checksum FROM schema_migrations`);
  const known = new Map(rows.map((r) => [String(r.name), String(r.checksum)]));

  const applied: string[] = [];
  const skipped: string[] = [];

  for (const name of await listMigrationFiles(dir)) {
    const sql = await fs.readFile(path.join(dir, name), "utf8");
    const checksum = createHash("sha256").update(sql).digest("hex");

    const recorded = known.get(name);
    if (recorded) {
      if (recorded !== checksum) {
        throw new Error(
          `Migration "${name}" was modified after it was applied ` +
            `(recorded ${recorded.slice(0, 12)}, file ${checksum.slice(0, 12)}). ` +
            `Add a new migration instead of editing an applied one.`,
        );
      }
      skipped.push(name);
      continue;
    }

    await pool.query("BEGIN");
    try {
      await pool.query(sql);
      await pool.query(
        `INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)`,
        [name, checksum],
      );
      await pool.query("COMMIT");
      applied.push(name);
    } catch (err) {
      await pool.query("ROLLBACK");
      throw new Error(`Migration "${name}" failed and was rolled back: ${(err as Error).message}`);
    }
  }

  return { applied, skipped };
}
