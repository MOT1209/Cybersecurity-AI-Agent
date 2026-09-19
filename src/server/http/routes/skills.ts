/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Skill platform routes: read-only registry listing and per-skill detail,
 * including every package that failed to load and exactly why. Nothing here
 * lets a caller execute a skill — there is no execution path yet (see
 * src/server/skills/registry.ts's module doc).
 */

import type { Express, Response } from "express";
import { validateStringField } from "../../core/index";
import { listSkills, getSkill, listSkillLoadFailures, isSkillExecutable } from "../../skills/index";

export function registerSkillsRoutes(app: Express) {
  app.get("/api/skills", (_req, res: Response) => {
    res.json({
      skills: listSkills().map((s) => ({
        id: s.manifest.id,
        name: s.manifest.name,
        version: s.manifest.version,
        riskLevel: s.manifest.riskLevel,
        capabilities: s.manifest.capabilities,
        requiredTools: s.manifest.requiredTools,
        requiredMcp: s.manifest.requiredMcp,
        executable: isSkillExecutable(s.manifest.id),
        scan: s.scan,
      })),
      loadFailures: listSkillLoadFailures(),
    });
  });

  app.get("/api/skills/:id", (req, res: Response) => {
    const check = validateStringField(req.params.id, "id", 100, true);
    if (!check.valid) {
      return res.status(400).json({ error: "VALIDATION_ERROR", message: check.error });
    }
    const skill = getSkill(req.params.id);
    if (!skill) {
      return res.status(404).json({ error: "SKILL_NOT_REGISTERED", message: `No skill "${req.params.id}" is registered.` });
    }
    res.json({
      manifest: skill.manifest,
      sourceDir: skill.sourceDir,
      loadedAt: skill.loadedAt,
      executable: isSkillExecutable(skill.manifest.id),
      scan: skill.scan,
    });
  });
}
