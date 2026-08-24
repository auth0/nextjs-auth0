import { describe, expect, it } from "vitest";

import { InvalidConfigurationError } from "../errors/index.js";
import {
  applyEnterpriseConnectRestrictions,
  EC_ALLOWED_GETTERS,
  EC_ALLOWED_METHODS,
  EC_SYNC_METHODS
} from "./enterprise-connect.js";

describe("applyEnterpriseConnectRestrictions", () => {
  describe("methods", () => {
    it("leaves allowed methods callable", () => {
      class FakeClient {
        middleware() {
          return "ok";
        }
        startInteractiveLogin() {
          return "ok";
        }
        startEnterpriseLogin() {
          return "ok";
        }
        customTokenExchange() {
          return "ok";
        }
      }

      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      for (const method of EC_ALLOWED_METHODS) {
        expect(
          typeof (instance as unknown as Record<string, unknown>)[method]
        ).toBe("function");
        expect(() =>
          (instance as unknown as Record<string, () => unknown>)[method]()
        ).not.toThrow();
      }
    });

    it("blocks methods not in the allowlist", async () => {
      class FakeClient {
        allowed() {
          return "ok";
        }
        blocked() {
          return "should not reach";
        }
      }

      const allowedBackup = new Set(EC_ALLOWED_METHODS);
      EC_ALLOWED_METHODS.clear();
      EC_ALLOWED_METHODS.add("allowed");

      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      expect(
        (instance as unknown as Record<string, () => unknown>).allowed()
      ).toBe("ok");
      await expect(
        (
          instance as unknown as Record<string, () => Promise<unknown>>
        ).blocked()
      ).rejects.toThrow(InvalidConfigurationError);

      EC_ALLOWED_METHODS.clear();
      allowedBackup.forEach((m) => EC_ALLOWED_METHODS.add(m));
    });

    it("includes the method name in the blocked error message", async () => {
      class FakeClient {
        doSomething() {
          return "x";
        }
      }

      EC_ALLOWED_METHODS.delete("doSomething");
      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      await expect(
        (
          instance as unknown as Record<string, () => Promise<unknown>>
        ).doSomething()
      ).rejects.toThrow(
        /doSomething\(\) is not available when enterpriseConnect is true/
      );

      EC_ALLOWED_METHODS.add("doSomething"); // restore is harmless since it wasn't there before
    });

    it("async blocked methods return a rejected promise, not a synchronous throw", () => {
      class FakeClient {
        async asyncBlocked() {
          return "x";
        }
      }

      EC_ALLOWED_METHODS.delete("asyncBlocked");
      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      let result: unknown;
      expect(() => {
        result = (
          instance as unknown as Record<string, () => unknown>
        ).asyncBlocked();
      }).not.toThrow();

      return expect(result).rejects.toThrow(InvalidConfigurationError);
    });

    it("sync methods listed in EC_SYNC_METHODS throw synchronously", () => {
      class FakeClient {
        syncMethod() {
          return "x";
        }
      }

      EC_ALLOWED_METHODS.delete("syncMethod");
      EC_SYNC_METHODS.add("syncMethod");
      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      expect(() =>
        (instance as unknown as Record<string, () => unknown>).syncMethod()
      ).toThrow(InvalidConfigurationError);

      EC_SYNC_METHODS.delete("syncMethod");
    });

    it("does not override the constructor", () => {
      class FakeClient {
        value = 42;
      }

      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      expect(instance.value).toBe(42);
    });
  });

  describe("getters", () => {
    it("leaves allowed getters accessible", () => {
      class FakeClient {
        get allowedGetter() {
          return "ok";
        }
      }

      EC_ALLOWED_GETTERS.add("allowedGetter");
      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      expect(
        (instance as unknown as Record<string, unknown>).allowedGetter
      ).toBe("ok");

      EC_ALLOWED_GETTERS.delete("allowedGetter");
    });

    it("blocks getters not in the allowlist", () => {
      class FakeClient {
        get blockedGetter() {
          return "should not reach";
        }
      }

      EC_ALLOWED_GETTERS.delete("blockedGetter");
      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      expect(
        () => (instance as unknown as Record<string, unknown>).blockedGetter
      ).toThrow(InvalidConfigurationError);
    });

    it("includes the getter name in the blocked error message", () => {
      class FakeClient {
        get myGetter() {
          return "x";
        }
      }

      EC_ALLOWED_GETTERS.delete("myGetter");
      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      expect(
        () => (instance as unknown as Record<string, unknown>).myGetter
      ).toThrow(/myGetter is not available when enterpriseConnect is true/);
    });
  });

  describe("guidance messages", () => {
    it("appends guidance when the member has an entry in EC_MEMBER_GUIDANCE", () => {
      class FakeClient {
        getSession() {
          return null;
        }
      }

      EC_ALLOWED_METHODS.delete("getSession");
      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      return expect(
        (
          instance as unknown as Record<string, () => Promise<unknown>>
        ).getSession()
      ).rejects.toThrow(
        /Read the user from the session store you populated in onCallback/
      );
    });

    it("falls back to the generic message when no guidance is registered", () => {
      class FakeClient {
        unknownMethod() {
          return "x";
        }
      }

      EC_ALLOWED_METHODS.delete("unknownMethod");
      const instance = new FakeClient();
      applyEnterpriseConnectRestrictions(instance);

      return expect(
        (
          instance as unknown as Record<string, () => Promise<unknown>>
        ).unknownMethod()
      ).rejects.toThrow(
        /unknownMethod\(\) is not available when enterpriseConnect is true\./
      );
    });
  });
});
