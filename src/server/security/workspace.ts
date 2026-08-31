/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Workspace containment for filesystem-scoped tools (SAST, dependency and
 * filesystem scanning).
 *
 * Code scanners genuinely need to read code, which means a bind mount — the one
 * exception to "no bind mounts". It is made safe by containment rather than by
 * trust: a path is only mountable when its REAL path (symlinks resolved) sits
 * inside the configured workspace root, and it is always mounted read-only.
 *
 * Resolving before checking is the point: `workspaces/../../etc` and a symlink
 * pointing out of the tree both fail here, where a string prefix check would
 * have let them through.
 */

import path from "path";
import fs from "fs/promises";

export const WORKSPACE_ROOT = () =>
  path.resolve(process.env.SANDBOX_WORKSPACE_ROOT || path.join(process.cwd(), "workspaces"));

/** Mount point inside the container. Read-only, always this path. */
export const CONTAINER_WORKSPACE = "/workspace";

export interface WorkspaceResolution {
  ok: boolean;
  /** Absolute, symlink-resolved host path. Only set when ok. */
  hostPath?: string;
  /** Path to pass to the tool inside the container. Only set when ok. */
  containerPath?: string;
  error?: string;
}

/**
 * Resolve a caller-supplied path to a mountable host path, or explain why it
 * cannot be mounted. Fails closed on anything it cannot verify.
 */
export async function resolveWorkspacePath(input: string): Promise<WorkspaceResolution> {
  if (typeof input !== "string" || !input.trim()) {
    return { ok: false, error: "A workspace path is required." };
  }
  if (input.includes("\0")) {
    return { ok: false, error: "Path contains a null byte." };
  }

  const root = WORKSPACE_ROOT();
  const candidate = path.resolve(root, input);

  let realRoot: string;
  try {
    realRoot = await fs.realpath(root);
  } catch {
    return {
      ok: false,
      error: `Workspace root "${root}" does not exist. Create it, or set SANDBOX_WORKSPACE_ROOT.`,
    };
  }

  let realPath: string;
  try {
    realPath = await fs.realpath(candidate);
  } catch {
    return { ok: false, error: `Path "${input}" does not exist inside the workspace root.` };
  }

  // Containment check on the RESOLVED paths, so symlinks and .. cannot escape.
  const rel = path.relative(realRoot, realPath);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
    return {
      ok: false,
      error: `Path "${input}" resolves outside the workspace root and cannot be mounted.`,
    };
  }

  const stat = await fs.stat(realPath);
  if (!stat.isDirectory() && !stat.isFile()) {
    return { ok: false, error: `Path "${input}" is neither a file nor a directory.` };
  }

  return {
    ok: true,
    hostPath: realPath,
    containerPath: path.posix.join(CONTAINER_WORKSPACE, rel.split(path.sep).join("/")),
  };
}
