/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guards the CTF challenge data against the class of bug that made CTF-02
 * unsolvable: an encoded payload that does not actually decode to the flag the
 * challenge declares. Every encoding-based challenge is checked mechanically
 * rather than by eye.
 */

import { describe, it, expect } from "vitest";
import { CTF_SCENARIOS } from "../src/data/cyberData";

/** Pull the long hex blob out of a scenario body. */
function extractHex(text: string): string | null {
  const m = text.match(/\b([0-9a-fA-F]{40,})\b/);
  return m ? m[1] : null;
}

describe("CTF challenge data integrity", () => {
  it("every scenario declares a non-empty flag", () => {
    expect(CTF_SCENARIOS.length).toBeGreaterThan(0);
    for (const s of CTF_SCENARIOS) {
      expect(s.flag, `${s.id} has no flag`).toBeTruthy();
    }
  });

  it("CTF-02's hex payload decodes through base64 to its declared flag", () => {
    const s = CTF_SCENARIOS.find((x) => x.id === "ctf-02");
    expect(s, "ctf-02 missing").toBeDefined();

    const hex = extractHex(s!.scenarioDetails);
    expect(hex, "no hex payload found in scenarioDetails").toBeTruthy();

    const b64 = Buffer.from(hex!, "hex").toString("utf8");
    const decoded = Buffer.from(b64, "base64").toString("utf8");

    expect(decoded).toBe(s!.flag);
  });

  it("CTF-02's hint names the real base64 prefix", () => {
    const s = CTF_SCENARIOS.find((x) => x.id === "ctf-02")!;
    const b64 = Buffer.from(extractHex(s.scenarioDetails)!, "hex").toString("utf8");
    const prefixHint = s.hints.find((h) => h.includes("Base64") && h.includes("..."));

    expect(prefixHint, "no prefix hint found").toBeTruthy();
    const claimed = prefixHint!.match(/([A-Za-z0-9+/]{4,})\.\.\./)?.[1];
    expect(claimed, "hint states no prefix").toBeTruthy();
    expect(b64.startsWith(claimed!)).toBe(true);
  });
});
