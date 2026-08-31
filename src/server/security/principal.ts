/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Principals and roles.
 *
 * V1 had one shared API key and no notion of who was calling, which made the
 * "approver must differ from requester" rule unenforceable against a determined
 * caller: everyone was the same identity. This module gives each key a distinct
 * principal and a role set, so authorization can be about *who*, not just
 * *whether you have the key*.
 *
 * Keys are configured as `id:role1|role2:secret` entries in API_PRINCIPALS and
 * are compared in constant time against a stored sha256 — the raw secret is
 * never held in memory after startup.
 */

import crypto from "crypto";

export type Role = "admin" | "operator" | "approver" | "viewer";

const VALID_ROLES: readonly Role[] = ["admin", "operator", "approver", "viewer"];

export interface Principal {
  id: string;
  roles: Role[];
}

interface StoredPrincipal extends Principal {
  /** sha256 of the secret. The secret itself is discarded after parsing. */
  secretHash: Buffer;
}

let principals: StoredPrincipal[] | null = null;

function sha256(v: string): Buffer {
  return crypto.createHash("sha256").update(v).digest();
}

/**
 * Parse API_PRINCIPALS. Format, comma-separated:
 *   `alice:admin|approver:s3cret,scanner-bot:operator:othersecret`
 *
 * A malformed or role-less entry is dropped rather than defaulted to something
 * permissive: an unparseable principal must not become an admin.
 */
export function parsePrincipals(raw: string | undefined): StoredPrincipal[] {
  if (!raw?.trim()) return [];
  const out: StoredPrincipal[] = [];
  for (const entry of raw.split(",")) {
    const parts = entry.trim().split(":");
    if (parts.length !== 3) continue;
    const [id, roleSpec, secret] = parts.map((p) => p.trim());
    if (!id || !secret) continue;
    const roles = roleSpec
      .split("|")
      .map((r) => r.trim().toLowerCase())
      .filter((r): r is Role => (VALID_ROLES as readonly string[]).includes(r));
    if (!roles.length) continue;
    out.push({ id, roles, secretHash: sha256(secret) });
  }
  return out;
}

function load(): StoredPrincipal[] {
  if (principals === null) principals = parsePrincipals(process.env.API_PRINCIPALS);
  return principals;
}

/** Test/config helper: re-read API_PRINCIPALS on the next lookup. */
export function resetPrincipals(): void {
  principals = null;
}

/** True when per-principal auth is configured at all. */
export function principalsConfigured(): boolean {
  return load().length > 0;
}

/**
 * Resolve a presented key to a principal, comparing in constant time. Every
 * candidate is checked so the loop's duration does not reveal which id matched.
 */
export function resolvePrincipal(presentedKey: string | undefined): Principal | null {
  if (!presentedKey) return null;
  const presented = sha256(presentedKey);
  let match: StoredPrincipal | null = null;
  for (const p of load()) {
    if (crypto.timingSafeEqual(presented, p.secretHash)) match = p;
  }
  return match ? { id: match.id, roles: match.roles } : null;
}

/** `admin` implies every other role. */
export function hasRole(principal: Principal | null, role: Role): boolean {
  if (!principal) return false;
  return principal.roles.includes("admin") || principal.roles.includes(role);
}

/**
 * The principal used when only the legacy shared APP_ACCESS_KEY is configured.
 * It deliberately lacks `approver`: a shared key is not an identity, so it must
 * not be able to satisfy a human-approval requirement.
 */
export const SHARED_KEY_PRINCIPAL: Principal = {
  id: "shared-api-key",
  roles: ["operator", "viewer"],
};

/** The principal for fully open local development (no key configured at all). */
export const ANONYMOUS_PRINCIPAL: Principal = {
  id: "anonymous-dev",
  roles: ["operator", "viewer"],
};
