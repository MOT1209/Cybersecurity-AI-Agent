/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Skill registry. Loads every skill package once at startup, security-scans
 * each one, and holds the result — mirroring the tool registry's and agent
 * catalog's pattern of computing a live status rather than trusting a
 * hand-maintained label.
 *
 * IMPORTANT — what this registry does NOT do: it does not execute skills. No
 * dispatch path from an agent or the orchestrator calls into this module yet.
 * A skill can be REGISTERED (loaded, scanned, and would be runnable if
 * something called it) without the platform ever actually invoking it. That
 * wiring — an agent selecting and running a skill — is real remaining work,
 * not implied by this file's existence. "Never execute an untrusted skill
 * automatically" is trivially true right now because nothing executes any
 * skill yet.
 */

import type { SkillManifest } from "./manifest";
import { discoverSkills, defaultSkillsRoot, type SkillLoadFailure } from "./loader";
import { scanSkillManifest, type SkillScanResult } from "./scanner";

export interface SkillRecord {
  manifest: SkillManifest;
  sourceDir: string;
  scan: SkillScanResult;
  loadedAt: string;
}

const registry = new Map<string, SkillRecord>();
let loadFailures: SkillLoadFailure[] = [];
let initialized = false;

/**
 * Discover, validate, and security-scan every skill package under `root`.
 * Idempotent-by-default (skips re-scanning if already initialized) unless
 * `force` is set — tests use `force` to reload against a temp fixture root.
 */
export async function initializeSkillRegistry(
  root: string = defaultSkillsRoot(),
  force = false,
): Promise<{ registered: number; failed: number }> {
  if (initialized && !force) {
    return { registered: registry.size, failed: loadFailures.length };
  }
  registry.clear();
  loadFailures = [];

  const { loaded, failed } = await discoverSkills(root);
  loadFailures = failed;

  // Two passes: first register every manifest that parsed, so the second
  // pass's dependency check can see sibling skills regardless of directory
  // iteration order.
  const knownIds = new Set(loaded.map((s) => s.manifest.id));
  for (const skill of loaded) {
    const scan = scanSkillManifest(skill.manifest, knownIds);
    registry.set(skill.manifest.id, {
      manifest: skill.manifest,
      sourceDir: skill.sourceDir,
      scan,
      loadedAt: new Date().toISOString(),
    });
  }

  initialized = true;
  return { registered: registry.size, failed: loadFailures.length };
}

export function isSkillRegistered(id: string): boolean {
  return registry.has(id);
}

export function getSkill(id: string): SkillRecord | undefined {
  return registry.get(id);
}

/** True only when the skill loaded, passed every scan check, and every
 *  required tool is a real adapter — the platform's actual bar for "could
 *  run this today," not merely "a skill.json exists." */
export function isSkillExecutable(id: string): boolean {
  return registry.get(id)?.scan.passed === true;
}

export function listSkills(): SkillRecord[] {
  return [...registry.values()].sort((a, b) => a.manifest.id.localeCompare(b.manifest.id));
}

export function listSkillLoadFailures(): SkillLoadFailure[] {
  return loadFailures;
}
