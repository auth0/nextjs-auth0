import { describe, expect, it } from "vitest";

import { AccessTokenSet, SessionData } from "../types/index.js";
import {
  accessTokenSetFromTokenSet,
  compareScopes,
  findAccessTokenSet
} from "./token-set-helpers.js";

function createSessionData(
  sessionData: Partial<SessionData> = {}
): SessionData {
  return {
    user: { sub: "user123", name: "Test User" },
    internal: { sid: "session123", createdAt: Date.now() },
    tokenSet: {
      accessToken: "<my_access_token>",
      expiresAt: Date.now() / 1000 + 3600
    },
    ...sessionData
  };
}

describe("token-set-helpers", () => {
  describe("accessTokenSetFromTokenSet", () => {
    it("should create an AccessTokenSet from a TokenSet", () => {
      const session = createSessionData();
      const options = {
        audience: "<my_audience>"
      };

      expect(accessTokenSetFromTokenSet(session.tokenSet, options)).toEqual({
        accessToken: session.tokenSet.accessToken,
        expiresAt: session.tokenSet.expiresAt,
        audience: options.audience,
        scope: session.tokenSet.scope
      });
    });
  });

  describe("findAccessTokenSet", () => {
    it("should find the AccessTokenSet when it is the only entry", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a b",
        audience: "<my_audience>"
      };
      const session = createSessionData({
        accessTokens: [accessTokenSet]
      });
      const options = {
        scope: "a",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
    });

    it("should find the AccessTokenSet when it is not the only entry", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a b",
        audience: "<my_audience>"
      };

      const accessTokenSet2: AccessTokenSet = {
        accessToken: "<my_custom_access_token_2>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "c d",
        audience: "<my_audience>"
      };

      const session = createSessionData({
        accessTokens: [accessTokenSet2, accessTokenSet]
      });
      const options = {
        scope: "a",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
    });

    it("should find the AccessTokenSet when it is not the only exact match entry and requested scope is empty", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "",
        audience: "<my_audience>"
      };

      const accessTokenSet2: AccessTokenSet = {
        accessToken: "<my_custom_access_token_2>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "",
        audience: "<my_audience>"
      };

      const session = createSessionData({
        accessTokens: [accessTokenSet, accessTokenSet2]
      });
      const options = {
        scope: "",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
    });

    it("should find the AccessTokenSet when the scope match partial", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a b",
        audience: "<my_audience>"
      };

      const accessTokenSet2: AccessTokenSet = {
        accessToken: "<my_custom_access_token_2>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "c d",
        audience: "<my_audience>"
      };

      const session = createSessionData({
        accessTokens: [accessTokenSet2, accessTokenSet]
      });
      const options = {
        scope: "a",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
    });

    it("should find the AccessTokenSet when the scope match exact", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a b",
        audience: "<my_audience>"
      };

      const accessTokenSet2: AccessTokenSet = {
        accessToken: "<my_custom_access_token_2>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "c d",
        audience: "<my_audience>"
      };

      const session = createSessionData({
        accessTokens: [accessTokenSet2, accessTokenSet]
      });
      const options = {
        scope: "a b",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
    });

    it("should find the AccessTokenSet with the best match", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a b",
        audience: "<my_audience>"
      };

      const accessTokenSet2: AccessTokenSet = {
        accessToken: "<my_custom_access_token_2>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a",
        audience: "<my_audience>"
      };

      const accessTokenSet3: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a b c",
        audience: "<my_audience>"
      };

      const session = createSessionData({
        accessTokens: [accessTokenSet, accessTokenSet3, accessTokenSet2]
      });
      const options = {
        scope: "a",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBe(accessTokenSet2);
    });

    it("should find the AccessTokenSet with the best match without exact match and ignore duplicates", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a a a a a b",
        audience: "<my_audience>"
      };

      const accessTokenSet2: AccessTokenSet = {
        accessToken: "<my_custom_access_token_2>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a b c d",
        audience: "<my_audience>"
      };

      const accessTokenSet3: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a b c",
        audience: "<my_audience>"
      };

      const session = createSessionData({
        accessTokens: [accessTokenSet, accessTokenSet3, accessTokenSet2]
      });
      const options = {
        scope: "a",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
    });

    it("should not find the AccessTokenSet when accessTokens is undefined", () => {
      const session = createSessionData({
        accessTokens: undefined
      });
      const options = {
        scope: "a",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBeUndefined();
    });

    it("should not find the AccessTokenSet when accessTokens is empty array", () => {
      const session = createSessionData({
        accessTokens: []
      });
      const options = {
        scope: "a",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBeUndefined();
    });

    it("should not find the AccessTokenSet when no match", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<my_custom_access_token>",
        expiresAt: Date.now() / 1000 + 3600,
        scope: "a b",
        audience: "<my_audience>"
      };

      const session = createSessionData({
        accessTokens: [accessTokenSet]
      });
      const options = {
        scope: "c",
        audience: "<my_audience>"
      };

      expect(findAccessTokenSet(session, options)).toBeUndefined();
    });
  });

  describe("compareScopes", () => {
    it("should match scopes when more scopes are available", () => {
      const scopes = "a b";
      const requiredScopes = "a";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match exact scopes", () => {
      const scopes = "a b";
      const requiredScopes = "a b";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match exact scopes when leading whitespaces in scopes", () => {
      const scopes = "   a b";
      const requiredScopes = "a b";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match exact scopes when trailing whitespaces in scopes", () => {
      const scopes = "a b   ";
      const requiredScopes = "a b";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match exact scopes when additional whitespaces in scopes", () => {
      const scopes = "a    b";
      const requiredScopes = "a b";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match exact scopes when leading whitespaces in requiredScopes", () => {
      const scopes = "a b";
      const requiredScopes = "   a b";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match exact scopes when trailing whitespaces in requiredScopes", () => {
      const scopes = "a b";
      const requiredScopes = "a b  ";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match exact scopes when additional whitespaces in requiredScopes", () => {
      const scopes = "a b";
      const requiredScopes = "a    b";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match exact scopes in reverse order", () => {
      const scopes = "a b";
      const requiredScopes = "b a";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match when both empty", () => {
      const scopes = "";
      const requiredScopes = "";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should match when both undefined", () => {
      const scopes = undefined;
      const requiredScopes = undefined;

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should not match when scopes empty", () => {
      const scopes = "";
      const requiredScopes = "a b c d";

      expect(compareScopes(scopes, requiredScopes)).toBe(false);
    });

    it("should not match when requiredScopes empty", () => {
      const scopes = "a b";
      const requiredScopes = "";

      expect(compareScopes(scopes, requiredScopes)).toBe(false);
    });

    it("should not match when no scope included", () => {
      const scopes = "a b";
      const requiredScopes = "c d";

      expect(compareScopes(scopes, requiredScopes)).toBe(false);
    });

    it("should not match when some scopes not included", () => {
      const scopes = "a b";
      const requiredScopes = "a b c d";

      expect(compareScopes(scopes, requiredScopes)).toBe(false);
    });

    it("should not match when scopes is undefined and requiredScopes empty string", () => {
      expect(compareScopes(undefined, "")).toBe(false);
    });
  });
});
