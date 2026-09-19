# nmap-recon

Network reconnaissance skill wrapping the platform's real `nmap` tool adapter
(`src/server/tools/nmap.ts`). This is a metadata/contract package — it does
not bundle its own copy of nmap or its own execution logic. When something
eventually dispatches this skill, it must resolve `nmap` through the
platform's tool registry (`src/server/tools/registry.ts`) and go through the
same security gateway every direct tool call does. No skill bypasses the
gateway; declaring `requiredTools` does not grant a shortcut around it.

## Status

Registered and scan-passing as of this writing (see
`src/server/skills/registry.ts`), because `nmap` has a real, implemented
adapter. **Not yet wired to any execution path** — no agent or orchestrator
step currently selects or invokes skills at all. That dispatch layer is
future work, tracked in `docs/architecture/current-state.md`.

## Capabilities

- `port-scan` — TCP connect scan over a caller-specified port range.
- `service-detection` — optional `-sV` service/version fingerprinting.

## Security posture

- Risk: MEDIUM (matches the underlying `nmap` adapter's own classification).
- Scope-enforced: yes — any real invocation must pass the same
  `validateSecurityGateway` check as a direct tool call.
- Approval: not required at MEDIUM risk under the current policy table
  (`src/server/security/policy.ts`).

See `security/` in this package for the specific scan checks this manifest
was validated against.
