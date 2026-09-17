/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Volatility 3 memory-forensics adapter. Runs a curated plugin over a memory
 * image inside the workspace root and parses the JSON renderer output into
 * structured rows.
 *
 * Two deliberate restrictions:
 * - The plugin comes from a curated allowlist, not caller input. A free-form
 *   plugin name would be arbitrary code selection driven by the caller.
 * - `target` is the container-side path produced by the workspace resolver,
 *   already contained, and the mount is read-only. Memory images are large;
 *   parsed rows are capped so one image cannot flood the findings store.
 *
 * Image trust note: there is no official Volatility 3 container image, so the
 * default is the long-maintained community build `sk4la/volatility3` (official
 * Volatility 3 release plus Foundation symbol tables). Operators who vet
 * their own build point VOLATILITY_IMAGE at it — the descriptor reads the
 * image from the environment for exactly this reason.
 */

import { z } from "zod";
import type { ToolRunRequest, ToolRunResult } from "../sandbox/types";
import type { ToolAdapter, ToolDescriptor } from "./types";

export const VOLATILITY_TOOL_ID = "volatility";
export const volatilityImage = () => process.env.VOLATILITY_IMAGE || "sk4la/volatility3:latest";

/** Curated Volatility 3 plugins. Nothing else can be selected. */
export const ALLOWED_VOLATILITY_PLUGINS = [
  "windows.info",
  "windows.pslist",
  "windows.psscan",
  "windows.netscan",
  "windows.cmdline",
  "windows.malfind",
  "linux.pslist",
  "linux.bash",
  "mac.pslist",
] as const;

/** Accepted memory-image suffixes. Volatility fails loudly on anything else,
 *  so rejecting early turns a confusing tool error into a clear 400. */
export const MEMORY_IMAGE_EXTENSIONS = [
  ".raw", ".mem", ".vmem", ".dmp", ".img", ".elf", ".lime", ".bin",
] as const;

/** Cap on parsed rows: one image must not flood the findings store. */
export const MAX_VOLATILITY_ROWS = 100;

export const VolatilityParamsSchema = z.object({
  plugin: z.enum(ALLOWED_VOLATILITY_PLUGINS).optional().default("windows.pslist"),
});

export type VolatilityParams = z.infer<typeof VolatilityParamsSchema>;

/**
 * `target` is the container-side path produced by the workspace resolver, so
 * it is already contained. It is passed via `-f` as the image to analyze.
 */
export function buildVolatilityRequest(target: string, rawParams: unknown): ToolRunRequest {
  const params = VolatilityParamsSchema.parse(rawParams ?? {});
  const lower = target.toLowerCase();
  if (!MEMORY_IMAGE_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
    throw new z.ZodError([
      {
        code: "custom",
        path: ["target"],
        message: `target must be a memory image (${MEMORY_IMAGE_EXTENSIONS.join(", ")})`,
      },
    ]);
  }
  const args = ["vol", "--renderer", "json", "-f", target, params.plugin];
  return {
    toolId: VOLATILITY_TOOL_ID,
    target,
    args,
    image: volatilityImage(),
    params: { ...params },
  };
}

export interface VolatilityRow {
  [column: string]: unknown;
}

/**
 * Parse the Volatility 3 JSON renderer document (`{ columns, rows }`).
 * Returns [] for unparseable output — "no parseable result", never "clean".
 * Rows beyond MAX_VOLATILITY_ROWS are dropped and reported via `truncated`.
 */
export function parseVolatilityOutput(raw: string): { columns: string[]; rows: VolatilityRow[]; truncated: boolean } {
  const empty = { columns: [] as string[], rows: [] as VolatilityRow[], truncated: false };
  const start = raw.indexOf("{");
  if (start < 0) return empty;
  let doc: unknown;
  try {
    doc = JSON.parse(raw.slice(start));
  } catch {
    return empty;
  }
  if (typeof doc !== "object" || doc === null) return empty;
  const { columns, rows } = doc as { columns?: unknown; rows?: unknown };
  if (!Array.isArray(columns) || !columns.every((c) => typeof c === "string")) return empty;
  if (!Array.isArray(rows)) return empty;
  const mapped: VolatilityRow[] = [];
  for (const row of rows.slice(0, MAX_VOLATILITY_ROWS + 1)) {
    if (!Array.isArray(row)) continue;
    const record: VolatilityRow = {};
    columns.forEach((col, i) => {
      record[col] = row[i] ?? null;
    });
    mapped.push(record);
  }
  const truncated = mapped.length > MAX_VOLATILITY_ROWS;
  return { columns, rows: truncated ? mapped.slice(0, MAX_VOLATILITY_ROWS) : mapped, truncated };
}

/** Enrich a raw volatility ToolRunResult with parsed plugin rows. */
export function summarizeVolatilityResult(result: ToolRunResult): ToolRunResult {
  // The plugin name reaches structuredData through the executor's params echo;
  // parse only adds what the executor cannot know.
  const parsed = parseVolatilityOutput(result.rawOutput);
  return {
    ...result,
    structuredData: {
      ...result.structuredData,
      columns: parsed.columns,
      rows: parsed.rows,
      rowCount: parsed.rows.length,
      truncated: parsed.truncated,
    },
  };
}

/** Registry descriptor for the volatility adapter. */
export const volatilityDescriptor: ToolDescriptor = {
  id: VOLATILITY_TOOL_ID,
  name: "Volatility 3 Memory Forensics Engine",
  version: "1.0.0",
  description:
    "Memory-image analysis over workspace evidence with Volatility 3. Offline " +
    "and read-only: no network, curated plugin allowlist, rows capped.",
  capabilities: ["memory-forensics"],
  inputSchema: VolatilityParamsSchema,
  outputSchemaHint:
    '{ plugin, columns: string[], rows: Record<string, unknown>[], rowCount, truncated }',
  permissions: ["workspace:read"],
  riskLevel: "LOW",
  timeoutMs: 300_000,
  resourceLimits: { cpus: 2, memoryMb: 2048, pids: 256 },
  sandboxRequired: true,
  needsNetwork: false,
  targetKind: "filesystem",
  filesystemAccess: "workspace-ro",
  get image() {
    return volatilityImage();
  },
};

/** The executable volatility adapter registered in the tool registry. */
export const volatilityAdapter: ToolAdapter = {
  descriptor: volatilityDescriptor,
  build: buildVolatilityRequest,
  parse: summarizeVolatilityResult,
};
