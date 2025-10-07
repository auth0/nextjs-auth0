import { describe, expect, it } from "vitest";

import { AccessTokenSet, SessionData } from "../types/index.js";
import {
  accessTokenSetFromTokenSet,
  compareScopes,
  findAccessTokenSet,
  mergeScopes,
  tokenSetFromAccessTokenSet
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

  describe("tokenSetFromAccessTokenSet", () => {
    it("should merge an AccessTokenSet into a partial TokenSet", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<access_token>",
        expiresAt: 1234567890,
        scope: "read:messages write:messages",
        requestedScope: "read:messages write:messages delete:messages",
        audience: "https://api.example.com"
      };

      const tokenSet = {
        idToken: "<id_token>",
        refreshToken: "<refresh_token>"
      };

      const result = tokenSetFromAccessTokenSet(accessTokenSet, tokenSet);

      expect(result).toEqual({
        idToken: "<id_token>",
        refreshToken: "<refresh_token>",
        accessToken: "<access_token>",
        expiresAt: 1234567890,
        scope: "read:messages write:messages",
        requestedScope: "read:messages write:messages delete:messages",
        audience: "https://api.example.com"
      });
    });

    it("should handle undefined accessTokenSet", () => {
      const tokenSet = {
        idToken: "<id_token>",
        refreshToken: "<refresh_token>"
      };

      const result = tokenSetFromAccessTokenSet(undefined, tokenSet);

      expect(result).toEqual({
        idToken: "<id_token>",
        refreshToken: "<refresh_token>",
        accessToken: undefined,
        expiresAt: undefined,
        scope: undefined,
        requestedScope: undefined,
        audience: undefined
      });
    });

    it("should handle empty tokenSet", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<access_token>",
        expiresAt: 1234567890,
        scope: "read:messages",
        audience: "https://api.example.com"
      };

      const result = tokenSetFromAccessTokenSet(accessTokenSet, {});

      expect(result).toEqual({
        accessToken: "<access_token>",
        expiresAt: 1234567890,
        scope: "read:messages",
        requestedScope: undefined,
        audience: "https://api.example.com"
      });
    });

    it("should override tokenSet properties with accessTokenSet values", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<new_access_token>",
        expiresAt: 9999999999,
        scope: "read:messages",
        requestedScope: "read:messages write:messages",
        audience: "https://api.example.com"
      };

      const tokenSet = {
        accessToken: "<old_access_token>",
        expiresAt: 1111111111,
        scope: "old:scope",
        requestedScope: "old:requested:scope",
        audience: "https://old-api.example.com",
        idToken: "<id_token>",
        refreshToken: "<refresh_token>"
      };

      const result = tokenSetFromAccessTokenSet(accessTokenSet, tokenSet);

      expect(result).toEqual({
        idToken: "<id_token>",
        refreshToken: "<refresh_token>",
        accessToken: "<new_access_token>",
        expiresAt: 9999999999,
        scope: "read:messages",
        requestedScope: "read:messages write:messages",
        audience: "https://api.example.com"
      });
    });

    it("should handle accessTokenSet without optional fields", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<access_token>",
        expiresAt: 1234567890,
        audience: "https://api.example.com"
      };

      const tokenSet = {
        idToken: "<id_token>",
        refreshToken: "<refresh_token>"
      };

      const result = tokenSetFromAccessTokenSet(accessTokenSet, tokenSet);

      expect(result).toEqual({
        idToken: "<id_token>",
        refreshToken: "<refresh_token>",
        accessToken: "<access_token>",
        expiresAt: 1234567890,
        scope: undefined,
        requestedScope: undefined,
        audience: "https://api.example.com"
      });
    });

    it("should preserve additional tokenSet properties", () => {
      const accessTokenSet: AccessTokenSet = {
        accessToken: "<access_token>",
        expiresAt: 1234567890,
        scope: "read:messages",
        audience: "https://api.example.com"
      };

      const tokenSet = {
        idToken: "<id_token>",
        refreshToken: "<refresh_token>",
        customProperty: "custom_value"
      };

      const result = tokenSetFromAccessTokenSet(accessTokenSet, tokenSet);

      expect(result).toEqual({
        idToken: "<id_token>",
        refreshToken: "<refresh_token>",
        customProperty: "custom_value",
        accessToken: "<access_token>",
        expiresAt: 1234567890,
        scope: "read:messages",
        requestedScope: undefined,
        audience: "https://api.example.com"
      });
    });

    it("should handle both undefined accessTokenSet and empty tokenSet", () => {
      const result = tokenSetFromAccessTokenSet(undefined, {});

      expect(result).toEqual({
        accessToken: undefined,
        expiresAt: undefined,
        scope: undefined,
        requestedScope: undefined,
        audience: undefined
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

    describe("with matchMode: 'scope'", () => {
      it("should find exact match using scope field with strict comparison", () => {
        const accessTokenSet: AccessTokenSet = {
          accessToken: "<my_custom_access_token>",
          expiresAt: Date.now() / 1000 + 3600,
          scope: "a b",
          requestedScope: "a b c",
          audience: "<my_audience>"
        };

        const session = createSessionData({
          accessTokens: [accessTokenSet]
        });
        const options = {
          scope: "a b",
          audience: "<my_audience>",
          matchMode: "scope" as const
        };

        expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
      });

      it("should not find AccessTokenSet when scope has extra permissions (strict mode)", () => {
        const accessTokenSet: AccessTokenSet = {
          accessToken: "<my_custom_access_token>",
          expiresAt: Date.now() / 1000 + 3600,
          scope: "a b c",
          requestedScope: "a b c",
          audience: "<my_audience>"
        };

        const session = createSessionData({
          accessTokens: [accessTokenSet]
        });
        const options = {
          scope: "a b",
          audience: "<my_audience>",
          matchMode: "scope" as const
        };

        // Should not match because strict mode requires exact match
        expect(findAccessTokenSet(session, options)).toBeUndefined();
      });

      it("should not find AccessTokenSet when requesting more scopes than available", () => {
        const accessTokenSet: AccessTokenSet = {
          accessToken: "<my_custom_access_token>",
          expiresAt: Date.now() / 1000 + 3600,
          scope: "a b",
          requestedScope: "a b c",
          audience: "<my_audience>"
        };

        const session = createSessionData({
          accessTokens: [accessTokenSet]
        });
        const options = {
          scope: "a b c",
          audience: "<my_audience>",
          matchMode: "scope" as const
        };

        // Should not match because actual scope doesn't have 'c'
        expect(findAccessTokenSet(session, options)).toBeUndefined();
      });

      it("should match using scope field, not requestedScope field", () => {
        const accessTokenSet: AccessTokenSet = {
          accessToken: "<my_custom_access_token>",
          expiresAt: Date.now() / 1000 + 3600,
          scope: "a",
          requestedScope: "a b c",
          audience: "<my_audience>"
        };

        const session = createSessionData({
          accessTokens: [accessTokenSet]
        });
        const options = {
          scope: "a",
          audience: "<my_audience>",
          matchMode: "scope" as const
        };

        // Should match based on scope field "a", not requestedScope "a b c"
        expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
      });

      it("should handle scope order differences with strict mode", () => {
        const accessTokenSet: AccessTokenSet = {
          accessToken: "<my_custom_access_token>",
          expiresAt: Date.now() / 1000 + 3600,
          scope: "b a",
          requestedScope: "a b c",
          audience: "<my_audience>"
        };

        const session = createSessionData({
          accessTokens: [accessTokenSet]
        });
        const options = {
          scope: "a b",
          audience: "<my_audience>",
          matchMode: "scope" as const
        };

        // Should match because compareScopes handles order differences
        expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
      });

      it("should find best match among multiple candidates in scope mode", () => {
        const accessTokenSet1: AccessTokenSet = {
          accessToken: "<my_custom_access_token_1>",
          expiresAt: Date.now() / 1000 + 3600,
          scope: "a",
          requestedScope: "a b c",
          audience: "<my_audience>"
        };

        const accessTokenSet2: AccessTokenSet = {
          accessToken: "<my_custom_access_token_2>",
          expiresAt: Date.now() / 1000 + 3600,
          scope: "a",
          requestedScope: "a b",
          audience: "<my_audience>"
        };

        const session = createSessionData({
          accessTokens: [accessTokenSet1, accessTokenSet2]
        });
        const options = {
          scope: "a",
          audience: "<my_audience>",
          matchMode: "scope" as const
        };

        // Should return the first matching one (both have same scope)
        expect(findAccessTokenSet(session, options)).toBe(accessTokenSet1);
      });

      it("should work with empty scope in strict mode", () => {
        const accessTokenSet: AccessTokenSet = {
          accessToken: "<my_custom_access_token>",
          expiresAt: Date.now() / 1000 + 3600,
          scope: "",
          requestedScope: "a b",
          audience: "<my_audience>"
        };

        const session = createSessionData({
          accessTokens: [accessTokenSet]
        });
        const options = {
          scope: "",
          audience: "<my_audience>",
          matchMode: "scope" as const
        };

        expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
      });

      it("should not match when requestedScope matches but scope does not", () => {
        const accessTokenSet: AccessTokenSet = {
          accessToken: "<my_custom_access_token>",
          expiresAt: Date.now() / 1000 + 3600,
          scope: "x y z",
          requestedScope: "a b",
          audience: "<my_audience>"
        };

        const session = createSessionData({
          accessTokens: [accessTokenSet]
        });
        const options = {
          scope: "a b",
          audience: "<my_audience>",
          matchMode: "scope" as const
        };

        // Should not match because we're checking against scope field, not requestedScope
        expect(findAccessTokenSet(session, options)).toBeUndefined();
      });

      it("should fall back to scope when requestedScope is undefined", () => {
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
          scope: "a b",
          audience: "<my_audience>",
          matchMode: "scope" as const
        };

        expect(findAccessTokenSet(session, options)).toBe(accessTokenSet);
      });
    });
  });

  describe("compareScopes", () => {
    it("should match scopes when more scopes are available", () => {
      const scopes = "a b";
      const requiredScopes = "a";

      expect(compareScopes(scopes, requiredScopes)).toBe(true);
    });

    it("should not match scopes when more scopes are available and strict is true", () => {
      const scopes = "a b";
      const requiredScopes = "a";

      expect(compareScopes(scopes, requiredScopes, { strict: true })).toBe(
        false
      );
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

  describe("mergeScopes", () => {
    it("should merge two scope strings without duplicates", () => {
      const scopes1 = "read:messages write:messages";
      const scopes2 = "delete:messages";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe("read:messages write:messages delete:messages");
    });

    it("should merge two scope strings with duplicates", () => {
      const scopes1 = "read:messages write:messages";
      const scopes2 = "read:messages delete:messages";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe("read:messages write:messages delete:messages");
    });

    it("should handle undefined scope strings", () => {
      const scopes1 = "read:messages write:messages";
      const scopes2 = undefined;

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe("read:messages write:messages");
    });

    it("should handle null scope strings", () => {
      const scopes1 = null;
      const scopes2 = "read:messages write:messages";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe("read:messages write:messages");
    });

    it("should handle both undefined scope strings", () => {
      const result = mergeScopes(undefined, undefined);
      expect(result).toBe("");
    });

    it("should handle both null scope strings", () => {
      const result = mergeScopes(null, null);
      expect(result).toBe("");
    });

    it("should handle leading whitespace in scopes", () => {
      const scopes1 = "   read:messages write:messages";
      const scopes2 = "delete:messages";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe("read:messages write:messages delete:messages");
    });

    it("should handle trailing whitespace in scopes", () => {
      const scopes1 = "read:messages write:messages   ";
      const scopes2 = "delete:messages";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe("read:messages write:messages delete:messages");
    });

    it("should handle multiple consecutive spaces in scopes", () => {
      const scopes1 = "read:messages    write:messages";
      const scopes2 = "delete:messages   read:messages";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe("read:messages write:messages delete:messages");
    });

    it("should remove duplicate scopes", () => {
      const scopes1 = "read:messages read:messages";
      const scopes2 = "read:messages write:messages";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe("read:messages write:messages");
    });

    it("should handle empty string scopes", () => {
      const scopes1 = "";
      const scopes2 = "read:messages";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe("read:messages");
    });

    it("should handle both empty string scopes", () => {
      const result = mergeScopes("", "");
      expect(result).toBe("");
    });

    it("should handle complex real-world scenario", () => {
      const scopes1 = "openid profile email offline_access";
      const scopes2 = "read:messages write:messages openid";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe(
        "openid profile email offline_access read:messages write:messages"
      );
    });

    it("should handle scopes with unusual characters", () => {
      const scopes1 = "read:user/profile write:user/settings";
      const scopes2 = "delete:user/account read:user/profile";

      const result = mergeScopes(scopes1, scopes2);
      expect(result).toBe(
        "read:user/profile write:user/settings delete:user/account"
      );
    });
  });
});
