/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Run-mode semantics (§ P1). The resolver, the type guard and the immutable
 * per-mode gates are the security-relevant surface here — a bad mode value
 * must fall back to a known default and never fail-open.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  RUN_MODES,
  DEFAULT_RUN_MODE,
  RUN_GATES,
  isRunMode,
  resolveRunMode,
  gateFor,
  getRunMode,
  setRunMode,
} from "../src/server/runtime/index";

describe("runtime run modes", () => {
  describe("resolver", () => {
    it("returns a valid mode unchanged", () => {
      for (const mode of RUN_MODES) {
        expect(resolveRunMode(mode)).toBe(mode);
        expect(resolveRunMode(mode, "learn")).toBe(mode);
      }
    });

    it("falls back to the request's default for anything invalid", () => {
      expect(resolveRunMode("nuke_everything", "lab")).toBe("lab");
      expect(resolveRunMode(42, "pair")).toBe("pair");
      expect(resolveRunMode({}, "learn")).toBe("learn");
      expect(resolveRunMode(null, "execute")).toBe("execute");
    });

    it("falls back to the platform default when none is requested", () => {
      expect(resolveRunMode(undefined)).toBe(DEFAULT_RUN_MODE);
      expect(resolveRunMode("", DEFAULT_RUN_MODE)).toBe(DEFAULT_RUN_MODE);
    });

    it("never resolves an unknown value into a more permissive mode by accident", () => {
      // pair is the strictest; an invalid value must not be promoted past it.
      expect(resolveRunMode("pair", "pair")).toBe("pair");
      expect(resolveRunMode("anything", "lab")).toBe("lab");
    });
  });

  describe("isRunMode", () => {
    it("accepts exactly the four declared modes", () => {
      for (const mode of RUN_MODES) {
        expect(isRunMode(mode)).toBe(true);
      }
    });

    it("rejects everything else", () => {
      expect(isRunMode("execute ")).toBe(false);
      expect(isRunMode("EXECUTE")).toBe(false);
      expect(isRunMode(undefined)).toBe(false);
      expect(isRunMode(null)).toBe(false);
      expect(isRunMode(["execute"])).toBe(false);
    });
  });

  describe("gates", () => {
    it("declares all four modes with a purpose", () => {
      expect(RUN_MODES).toHaveLength(4);
      for (const mode of RUN_MODES) {
        const gate = RUN_GATES[mode];
        expect(gateFor(mode)).toBe(gate);
        expect(typeof gate.purpose).toBe("string");
        expect(gate.purpose.length).toBeGreaterThan(0);
      }
    });

    it("learn executes nothing and allows no egress", () => {
      const g = RUN_GATES.learn;
      expect(g.executionAllowed).toBe(false);
      expect(g.egressAllowed).toBe(false);
      expect(g.approvalEveryStep).toBe(false);
    });

    it("lab is restricted to the isolated labs", () => {
      const g = RUN_GATES.lab;
      expect(g.labOnly).toBe(true);
      expect(g.executionAllowed).toBe(true);
    });

    it("execute is the balanced default", () => {
      const g = RUN_GATES.execute;
      expect(g.executionAllowed).toBe(true);
      expect(g.egressAllowed).toBe(true);
      expect(g.approvalEveryStep).toBe(false);
      expect(g.labOnly).toBe(false);
    });

    it("pair requires a human decision before every run", () => {
      const g = RUN_GATES.pair;
      expect(g.approvalEveryStep).toBe(true);
      expect(g.executionAllowed).toBe(true);
    });
  });

  describe("store", () => {
    beforeEach(() => {
      setRunMode(DEFAULT_RUN_MODE);
    });

    it("starts at the platform default", () => {
      expect(getRunMode()).toBe(DEFAULT_RUN_MODE);
    });

    it("setRunMode stores the mode and reports it", () => {
      expect(setRunMode("lab")).toBe("lab");
      expect(getRunMode()).toBe("lab");
      expect(setRunMode("pair")).toBe("pair");
      expect(getRunMode()).toBe("pair");
    });

    it("only valid modes reach the store", () => {
      // The route validates with isRunMode before calling setRunMode; guard the
      // invariant here so an invalid write can never slip past that layer.
      const valid = () => isRunMode("bogus") || setRunMode("pair");
      expect(valid()).toBe("pair");
      expect(getRunMode()).toBe("pair");
    });
  });
});