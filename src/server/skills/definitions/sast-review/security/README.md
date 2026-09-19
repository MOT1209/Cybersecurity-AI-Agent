# Security scan checks

See `src/server/skills/scanner.ts` for the authoritative logic.

1. `semgrep` has a real, implemented adapter.
2. `requiredMcp` is empty.
3. `permissions` (`filesystem:workspace-read`) is on the allowlist.
4. No dependencies to resolve.
5. `riskLevel` (LOW) does not require `ENABLE_CRITICAL_TOOLS`.
6. `securityPolicy.maxRiskLevel` (LOW) is not lower than `riskLevel` (LOW).
