/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Process entrypoint. The HTTP application itself lives in
 * src/server/http/app.ts; this file starts the server and re-exports
 * createApp so the test suite (and any consumer) keeps the same import.
 */

import { createApp } from "./src/server/http/app";
import { initDatabase } from "./src/server/database/index";

export { createApp };

async function startServer() {
  const PORT = Number(process.env.PORT) || 7799;

  // Resolve persistence BEFORE serving. When DATABASE_URL is set, an
  // unreachable server aborts startup rather than quietly running in memory
  // and losing every finding and audit record on restart.
  const db = await initDatabase();
  if (db.kind === "memory") {
    console.warn(
      "[persistence] Running IN MEMORY: findings, agent runs and audit records " +
        "are lost on restart and are not shared across replicas. Set DATABASE_URL " +
        "for a persistent backend.",
    );
  } else {
    console.log("[persistence] Postgres backend connected and migrated.");
  }

  const app = await createApp();
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`CYBERGUARD AI Platform Server active on http://0.0.0.0:${PORT}`);
  });
}

// Only auto-start when run directly, not when imported by tests.
if (process.env.NODE_ENV !== "test") {
  startServer().catch((err) => {
    console.error("Failed to start server:", err);
  });
}