# Tests

Executable tests for this skill package live at
`test/skills.test.ts` (repo-level, run via `npm run test`), not inside this
directory — the project's test runner (vitest) discovers from `test/`, and
duplicating fixtures here would create two sources of truth. This file is a
pointer, not a placeholder for missing coverage.
