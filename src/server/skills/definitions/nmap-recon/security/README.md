# Security scan checks

Evaluated by `src/server/skills/scanner.ts` at load time (see that file for
the authoritative logic — this is a human-readable summary, not a second
source of truth):

1. Every `requiredTools` entry (`nmap`) has a real, implemented adapter.
2. `requiredMcp` is empty — no MCP platform exists yet.
3. `permissions` (`network:scan`) is on the fixed platform allowlist.
4. `dependencies` (none) all resolve to registered skills.
5. `riskLevel` (MEDIUM) does not require `ENABLE_CRITICAL_TOOLS`.
6. `securityPolicy.maxRiskLevel` (MEDIUM) is not lower than `riskLevel` (MEDIUM).
