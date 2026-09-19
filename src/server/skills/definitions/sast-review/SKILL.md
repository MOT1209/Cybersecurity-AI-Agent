# sast-review

Static analysis skill wrapping the platform's real `semgrep` tool adapter
(`src/server/tools/semgrep.ts`). Filesystem-scoped: containment is enforced
by the workspace resolver (`src/server/security/workspace.ts`), not by
target scope matching.

## Status

Registered and scan-passing as of this writing, because `semgrep` has a
real, implemented adapter. **Not yet wired to any execution path** — see the
same caveat in `nmap-recon/SKILL.md`; it applies identically here.

## Security posture

- Risk: LOW (matches the underlying `semgrep` adapter's own classification).
- Never reaches the network — `needsNetwork: false` on the underlying tool.
- Scope-enforced: yes, via workspace containment rather than host allow/deny.
