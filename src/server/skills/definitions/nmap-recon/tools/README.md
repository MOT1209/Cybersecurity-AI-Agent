# Tools

This skill does not bundle its own tool binaries or wrapper scripts. It
declares `requiredTools: ["nmap"]` in `skill.json` and resolves that name
against the platform's own tool registry (`src/server/tools/registry.ts`) —
the same real adapter every direct `/api/tools/execute` call against `nmap`
uses. A skill that needed a tool the platform doesn't already have would
need that tool built as a real adapter first, not smuggled in here.
