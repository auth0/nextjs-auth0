import { describe, expect, it } from "vitest";

import { StatelessSessionStore } from "./stateless-session-store.js";

/**
 * Tests for AbstractSessionStore base class behaviors.
 * Uses StatelessSessionStore as a concrete implementation since
 * AbstractSessionStore cannot be instantiated directly.
 */
describe("AbstractSessionStore", () => {
  describe("deleteByReqCookies default no-op", () => {
    it("resolves without throwing when called on a store that does not override it", async () => {
      // StatelessSessionStore overrides deleteByReqCookies with an intentional no-op.
      // To hit the AbstractSessionStore default, we clear the override from the prototype chain
      // and call the base implementation directly.
      const store = new StatelessSessionStore({
        secret: "test-secret-long-enough-for-hs256-algorithm"
      });

      // Call the base class method directly, bypassing the subclass override
      const baseMethod = Object.getPrototypeOf(
        Object.getPrototypeOf(store)
      ).deleteByReqCookies;

      await expect(baseMethod.call(store, {} as any)).resolves.toBeUndefined();
    });
  });

  describe("isRolling getter", () => {
    it("returns true when rolling is enabled (default)", () => {
      const store = new StatelessSessionStore({
        secret: "test-secret-long-enough-for-hs256-algorithm"
      });
      expect(store.isRolling).toBe(true);
    });

    it("returns false when rolling is disabled", () => {
      const store = new StatelessSessionStore({
        secret: "test-secret-long-enough-for-hs256-algorithm",
        rolling: false
      });
      expect(store.isRolling).toBe(false);
    });
  });
});
