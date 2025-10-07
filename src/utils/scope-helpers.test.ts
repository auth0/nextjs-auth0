import { describe, expect, it } from "vitest";

import { DEFAULT_SCOPES } from "./constants.js";
import { ensureDefaultScope, getScopeForAudience } from "./scope-helpers.js";

describe("scope-helpers", () => {
  describe("ensureDefaultScope", () => {
    it("should return the DEFAULT_SCOPES as a string when no scope defined", () => {
      expect(ensureDefaultScope({})).toEqual(DEFAULT_SCOPES);
    });

    it("should return the DEFAULT_SCOPES in a map string when scope defined as map", () => {
      expect(() => ensureDefaultScope({ scope: {} })).toThrow(
        "When defining scope as a Map, an audience is required to look up the correct scope"
      );
    });

    it("should return the DEFAULT_SCOPES in a map string when scope defined as map", () => {
      const audience = "my-audience";
      expect(ensureDefaultScope({ audience, scope: {} })).toEqual({
        [audience]: DEFAULT_SCOPES
      });
    });

    it("should return the original scope when scope defined as map and contains default scope", () => {
      const audience = "my-audience";
      const authorizationParameters = {
        audience,
        scope: { [audience]: "read:messages write:messages" }
      };

      expect(ensureDefaultScope(authorizationParameters)).toEqual(
        authorizationParameters.scope
      );
    });
  });

  describe("getScopeForAudience", () => {
    it("should return undefined when the scope is undefined", () => {
      expect(getScopeForAudience(undefined, undefined)).toBeUndefined();
    });

    it("should return the scope as a string when it is defined as a string and audience is undefined", () => {
      const scope = "read:messages write:messages";
      expect(getScopeForAudience(scope, undefined)).toEqual(scope);
    });

    it("should return the scope as a string when it is defined as a string and audience is null", () => {
      const scope = "read:messages write:messages";
      expect(getScopeForAudience(scope, null)).toEqual(scope);
    });

    it("should return the scope as a string when it is defined as a string and audience is defined", () => {
      const scope = "read:messages write:messages";
      expect(getScopeForAudience(scope, "my-audience")).toEqual(scope);
    });

    it("should throw when scope is defined with a map but audience is not defined", () => {
      const scope = {
        "audience-1": "read:messages write:messages"
      };
      expect(() => getScopeForAudience(scope, undefined)).toThrow(
        "When defining scope as a Map, an audience is required to look up the correct scope."
      );
    });

    it("should return the scope for the audience as a string when scope is defined with a map and audience is defined", () => {
      const scope = {
        ["my-audience"]: "read:messages write:messages"
      };
      expect(getScopeForAudience(scope, "my-audience")).toEqual(
        "read:messages write:messages"
      );
    });

    it("should return undefined when scope is defined with a map and audience is not defined", () => {
      const scope = {
        "other-audience": "read:messages write:messages"
      };
      expect(getScopeForAudience(scope, "my-audience")).toBeUndefined();
    });
  });
});
