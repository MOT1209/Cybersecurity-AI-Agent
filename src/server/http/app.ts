/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * HTTP application assembly. Everything that used to live in server.ts is now
 * split by responsibility: the shared middleware in ./middleware, the Gemini
 * client factory in ./geminiClient, and one route group per domain in
 * ./routes. server.ts keeps only the process entrypoint and re-exports this
 * createApp.
 */

import express from "express";
import path from "path";
import helmet from "helmet";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
import {
  createGlobalApiLimiter,
  createGeminiAiLimiter,
  apiKeyAuthMiddleware,
} from "./middleware";
import { registerInfraRoutes } from "./routes/infra";
import { registerSecurityRoutes } from "./routes/security";
import { registerOrchestratorRoutes } from "./routes/orchestrator";
import { registerLabsRoutes } from "./routes/labs";
import { registerKnowledgeRoutes } from "./routes/knowledge";
import { registerToolsRoutes } from "./routes/tools";
import { registerIntrospectionRoutes } from "./routes/introspection";
import { registerGeminiRoutes } from "./routes/gemini";

dotenv.config();

export async function createApp() {
  const app = express();

  // Trust proxy for Cloud Run / Nginx reverse proxy environment
  app.set("trust proxy", 1);

  // Security headers. The default CSP is disabled outside production because
  // Vite's dev middleware serves inline scripts and opens an HMR websocket,
  // both of which a strict default policy blocks.
  app.use(
    helmet({
      contentSecurityPolicy: process.env.NODE_ENV === "production" ? undefined : false,
    }),
  );

  // 1MB is generous: the largest field any endpoint accepts is 4,000 chars.
  // The previous 15MB ceiling was memory-DoS surface with no functional use.
  app.use(express.json({ limit: "1mb" }));

  // Mount Global Limiters and Auth for /api
  app.use("/api", createGlobalApiLimiter());
  app.use("/api", apiKeyAuthMiddleware);

  // Mount Strict Limiter on Gemini and Orchestrator execution routes
  app.use("/api/gemini", createGeminiAiLimiter());
  app.use("/api/orchestrator/run-mission", createGeminiAiLimiter());

  // Route groups, each scoped to one domain of the platform.
  registerInfraRoutes(app); // health, database/status, projects, runtime/mode
  registerSecurityRoutes(app); // gateway check, approvals
  registerOrchestratorRoutes(app); // run-mission, error-recovery
  registerLabsRoutes(app); // labs
  registerKnowledgeRoutes(app); // knowledge search, findings
  registerToolsRoutes(app); // tools registry + health + execute
  registerIntrospectionRoutes(app); // agents, runs, events, logs
  registerGeminiRoutes(app); // chat + assistant endpoints

  // Static / dev asset serving. Skipped entirely under NODE_ENV=test so the
  // app can be exercised in isolation by the test suite.
  if (process.env.NODE_ENV === "test") {
    // no-op
  } else if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  return app;
}