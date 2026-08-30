/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Strict scope matching for the security gateway. Replaces the previous
 * substring (`String.includes`) checks — which allowed trivial bypasses such as
 * "192.168.1.50.attacker.com" — with structured host / IPv4 / CIDR / wildcard
 * matching. Pure and side-effect free so it is exhaustively unit-testable.
 */

/** Extract the bare host from a target: strips scheme, userinfo, path, port. */
export function extractHost(target: string): string {
  let t = target.trim().toLowerCase();
  t = t.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // scheme://
  t = t.split("/")[0]; // drop path/query
  const at = t.split("@");
  t = at[at.length - 1]; // drop userinfo
  if (t.startsWith("[")) {
    // bracketed IPv6 — return the inner address
    const m = t.match(/^\[(.+?)\]/);
    return m ? m[1] : t;
  }
  t = t.replace(/:\d+$/, ""); // drop :port
  return t;
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const CIDR_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;

export function isIPv4(host: string): boolean {
  const m = IPV4_RE.exec(host);
  if (!m) return false;
  return m.slice(1, 5).every((o) => Number(o) <= 255);
}

function ipv4ToInt(ip: string): number {
  const m = IPV4_RE.exec(ip);
  if (!m) return -1;
  return (
    ((Number(m[1]) << 24) | (Number(m[2]) << 16) | (Number(m[3]) << 8) | Number(m[4])) >>> 0
  );
}

/** True when `ip` (IPv4) falls inside `cidr` (e.g. "10.0.0.0/8"). */
export function ipInCidr(ip: string, cidr: string): boolean {
  const c = CIDR_RE.exec(cidr);
  if (!c || !isIPv4(ip)) return false;
  const bits = Number(c[5]);
  if (bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const base = ipv4ToInt(`${c[1]}.${c[2]}.${c[3]}.${c[4]}`);
  const addr = ipv4ToInt(ip);
  return (base & mask) === (addr & mask);
}

/** RFC1918 private ranges, loopback, localhost, and *.lab hosts (lab scope). */
export function isPrivateOrLabHost(host: string): boolean {
  if (host === "localhost") return true;
  if (host === "lab" || host.endsWith(".lab")) return true;
  if (!isIPv4(host)) return false;
  return (
    ipInCidr(host, "10.0.0.0/8") ||
    ipInCidr(host, "172.16.0.0/12") ||
    ipInCidr(host, "192.168.0.0/16") ||
    ipInCidr(host, "127.0.0.0/8")
  );
}

/**
 * True when `host` matches a single scope entry. Supports:
 *   - CIDR       "10.0.0.0/24"      → IPv4 membership
 *   - wildcard   "*.example.com"    → exact apex or any subdomain
 *   - host/URL   "http://h:8080/x"  → normalized to its host, exact match
 */
export function matchesScopeEntry(host: string, rawEntry: string): boolean {
  const entry = rawEntry.trim().toLowerCase();
  if (CIDR_RE.test(entry)) {
    return isIPv4(host) && ipInCidr(host, entry);
  }
  const e = extractHost(entry);
  if (e.startsWith("*.")) {
    const suffix = e.slice(2);
    return host === suffix || host.endsWith("." + suffix);
  }
  return host === e;
}

/** True when `host` matches any entry in `entries`. */
export function matchesAnyScope(host: string, entries: readonly string[]): boolean {
  return entries.some((e) => matchesScopeEntry(host, e));
}
