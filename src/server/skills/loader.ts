/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Skill discovery + loading. Reads `<dir>/skill.json` for every immediate
 * subdirectory of the skills root, validates it against SkillManifestSchema,
 * and requires `SKILL.md` to exist alongside it (a skill with no
 * human-readable documentation is not considered loadable — this mirrors the
 * platform's own "no fabricated completeness" stance).
 *
 * A malformed or incomplete skill package is skipped with a recorded reason,
 * never silently dropped and never coerced into looking valid.
 */

import fs from "fs/promises";
import path from "path";
import { SkillManifestSchema, type SkillManifest } from "./manifest";

export function defaultSkillsRoot(): string {
  return path.join(process.cwd(), "src", "server", "skills", "definitions");
}

export interface LoadedSkill {
  manifest: SkillManifest;
  sourceDir: string;
}

export interface SkillLoadFailure {
  dir: string;
  reason: string;
}

export interface DiscoverSkillsResult {
  loaded: LoadedSkill[];
  failed: SkillLoadFailure[];
}

/** Load and validate a single skill directory's skill.json + SKILL.md. */
export async function loadSkillDirectory(dir: string): Promise<LoadedSkill> {
  const manifestPath = path.join(dir, "skill.json");
  const docPath = path.join(dir, "SKILL.md");

  let raw: string;
  try {
    raw = await fs.readFile(manifestPath, "utf8");
  } catch {
    throw new Error(`missing skill.json in ${dir}`);
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(raw);
  } catch (err) {
    throw new Error(`skill.json in ${dir} is not valid JSON: ${(err as Error).message}`);
  }

  const result = SkillManifestSchema.safeParse(parsedJson);
  if (!result.success) {
    throw new Error(`skill.json in ${dir} failed schema validation: ${result.error.issues.map((i) => i.message).join("; ")}`);
  }

  try {
    await fs.access(docPath);
  } catch {
    throw new Error(`missing SKILL.md in ${dir} — undocumented skills are not loadable`);
  }

  return { manifest: result.data, sourceDir: dir };
}

/**
 * Discover every skill package under `root` (default: skills/definitions).
 * Never throws for a bad individual package — collects failures instead so
 * one broken skill can't take the whole registry down.
 */
export async function discoverSkills(root: string = defaultSkillsRoot()): Promise<DiscoverSkillsResult> {
  const loaded: LoadedSkill[] = [];
  const failed: SkillLoadFailure[] = [];

  let entries: string[];
  try {
    entries = (await fs.readdir(root, { withFileTypes: true }))
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch {
    // No skills directory at all is a valid, honest state (zero skills), not an error.
    return { loaded, failed };
  }

  for (const name of entries) {
    const dir = path.join(root, name);
    try {
      const skill = await loadSkillDirectory(dir);
      if (skill.manifest.id !== name) {
        failed.push({ dir, reason: `directory name "${name}" does not match manifest id "${skill.manifest.id}"` });
        continue;
      }
      loaded.push(skill);
    } catch (err) {
      failed.push({ dir, reason: (err as Error).message });
    }
  }

  return { loaded, failed };
}
