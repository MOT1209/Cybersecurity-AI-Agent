/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Skill dispatch — the piece that was explicitly missing when this platform
 * was first built: something that actually invokes a registered skill.
 *
 * Deliberately narrow: a skill in this platform currently wraps exactly one
 * tool (`requiredTools[0]`). A skill that orchestrates a pipeline of several
 * tools, or that runs logic beyond "resolve one tool adapter and execute
 * it," is not supported here yet — that is real remaining work, not
 * something this dispatcher pretends to do.
 *
 * Dispatching a skill goes through the exact same `executeTool()` path a
 * direct `/api/tools/execute` call does — the security gateway, human
 * approval, and sandbox isolation are not bypassed because the caller went
 * through a skill id instead of a tool id.
 */

import { getSkill, isSkillExecutable, initializeSkillRegistry } from "./registry";
import { getToolAdapter } from "../tools/registry";
import { executeTool } from "../sandbox/index";
import type { ToolRunResult } from "../sandbox/types";

export class SkillNotRegisteredError extends Error {
  readonly code = "SKILL_NOT_REGISTERED" as const;
  constructor(public readonly skillId: string) {
    super(`Skill "${skillId}" is not registered.`);
    this.name = "SkillNotRegisteredError";
  }
}

export class SkillNotExecutableError extends Error {
  readonly code = "SKILL_NOT_EXECUTABLE" as const;
  constructor(
    public readonly skillId: string,
    public readonly reasons: string[],
  ) {
    super(`Skill "${skillId}" failed its security scan and cannot be dispatched: ${reasons.join("; ")}`);
    this.name = "SkillNotExecutableError";
  }
}

export interface DispatchSkillOptions {
  projectId?: string;
  actor?: string;
  traceId?: string;
  /** Host path to bind read-only — required for a filesystem-scoped skill's tool. */
  workspaceHostPath?: string;
  /** Single-use approval token, for a skill whose underlying tool requires human approval. */
  approvalToken?: string;
}

/**
 * Resolve `skillId`'s single required tool, build a request through that
 * tool's real adapter, and run it through the normal gateway-guarded sandbox
 * path. Throws GatewayDeniedError/ApprovalRequiredError/ToolNotAvailableError
 * exactly as a direct tool call would — this function adds a skill-shaped
 * front door, not a second, laxer enforcement path.
 */
export async function dispatchSkill(
  skillId: string,
  target: string,
  params: unknown,
  opts: DispatchSkillOptions = {},
): Promise<ToolRunResult> {
  // Idempotent — a no-op if the HTTP app already initialized the registry at
  // startup. Needed because an agent can be dispatched directly (tests,
  // future non-HTTP entry points) without going through createApp() first.
  await initializeSkillRegistry();

  const skill = getSkill(skillId);
  if (!skill) throw new SkillNotRegisteredError(skillId);
  if (!isSkillExecutable(skillId)) {
    throw new SkillNotExecutableError(
      skillId,
      skill.scan.findings.filter((f) => !f.passed).map((f) => f.detail),
    );
  }

  const toolId = skill.manifest.requiredTools[0];
  if (!toolId) {
    throw new Error(`Skill "${skillId}" declares no requiredTools — there is nothing to dispatch.`);
  }
  // isSkillExecutable() already proved this tool is registered + implemented.
  const adapter = getToolAdapter(toolId)!;

  const built = adapter.build(target, params);
  const raw = await executeTool({
    toolId,
    target: built.target,
    args: built.args,
    image: built.image,
    params: built.params,
    projectId: opts.projectId,
    actor: opts.actor ?? `skill:${skillId}`,
    traceId: opts.traceId,
    workspaceHostPath: opts.workspaceHostPath,
    approvalToken: opts.approvalToken,
  });
  return adapter.parse(raw);
}
