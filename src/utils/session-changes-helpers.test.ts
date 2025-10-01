import { describe, expect, it } from "vitest";

import { SessionData } from "../types/index.js";
import { getSessionChangesAfterGetAccessToken } from "./session-changes-helpers.js";

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

describe("session-changes-helpers", () => {
  describe("getSessionChangesAfterGetAccessToken", () => {
    it("should get the sessionChanges when no scope and audience is provided", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, {})
      ).toEqual({
        tokenSet: {
          accessToken: tokenSet.accessToken,
          expiresAt: tokenSet.expiresAt,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken
        }
      });
    });

    it("should not get any sessionChanges when no scope and audience is provided but no changes", () => {
      const session = createSessionData();
      const tokenSet = {
        ...session.tokenSet
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, {})
      ).toBeUndefined();
    });

    it("should get the sessionChanges when scope and audience is provided but are the global values", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200,
        requestedScope: "read:messages",
        scope: "read:messages",
        audience: "https://api.example.com"
      };
      const globalOptions = {
        scope: "read:messages",
        audience: "https://api.example.com"
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
      ).toEqual({
        tokenSet: {
          accessToken: tokenSet.accessToken,
          expiresAt: tokenSet.expiresAt,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken,
          // TODO: Do we want to add these to the main tokenSet?
          requestedScope: "read:messages",
          scope: "read:messages",
          audience: "https://api.example.com"
        }
      });
    });

    it("should get the sessionChanges when scope and audience is provided and are not the global values", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200,
        scope: "write:messages",
        audience: "https://api.example.com"
      };

      const globalOptions = {
        scope: "read:messages",
        audience: "https://read-api.example.com"
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
      ).toEqual({
        tokenSet: {
          ...session.tokenSet,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken
        },
        accessTokens: [
          {
            accessToken: tokenSet.accessToken,
            expiresAt: tokenSet.expiresAt,
            scope: tokenSet.scope,
            audience: tokenSet.audience
          }
        ]
      });
    });

    it("should get the sessionChanges when scope and audience is provided, are not the global values and entry already exists", () => {
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200,
        scope: "write:messages",
        audience: "https://api.example.com"
      };
      const session = createSessionData({
        accessTokens: [
          {
            accessToken: "<my_old_access_token>",
            expiresAt: Date.now() / 1000 + 7200,
            requestedScope: tokenSet.scope,
            scope: tokenSet.scope,
            audience: tokenSet.audience
          },
          {
            accessToken: "<my_access_token>",
            expiresAt: Date.now() / 1000 + 7200,
            requestedScope: "scope-a",
            scope: "scope-a",
            audience: "<another_audience>"
          }
        ]
      });

      const globalOptions = {
        scope: "read:messages",
        audience: "https://read-api.example.com"
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
      ).toEqual({
        tokenSet: {
          ...session.tokenSet,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken
        },
        accessTokens: [
          {
            accessToken: tokenSet.accessToken,
            expiresAt: tokenSet.expiresAt,
            scope: tokenSet.scope,
            requestedScope: tokenSet.scope,
            audience: tokenSet.audience
          },
          {
            accessToken: session.accessTokens![1].accessToken,
            expiresAt: session.accessTokens![1].expiresAt,
            scope: session.accessTokens![1].scope,
            requestedScope: session.accessTokens![1].requestedScope,
            audience: session.accessTokens![1].audience
          }
        ]
      });
    });

    it("should get the sessionChanges when scope and no audience is provided", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200,
        scope: "a",
        requestedScope: "a"
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, {})
      ).toBeUndefined();
    });

    it("should get the sessionChanges when audience is provided, but no scope is provided and global scope is used", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200,
        scope: "default-scope",
        audience: "https://api.example.com"
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, {
          scope: "default-scope"
        })
      ).toEqual({
        tokenSet: {
          ...session.tokenSet,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken
        },
        accessTokens: [
          {
            accessToken: tokenSet.accessToken,
            audience: "https://api.example.com",
            scope: "default-scope",
            expiresAt: tokenSet.expiresAt
          }
        ]
      });
    });

    it("should get the sessionChanges when scope and audience is provided and are not the global values and requested scope differ, but provided scope are identical", () => {
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200,
        scope: "a",
        requestedScope: "a c",
        audience: "https://api.example.com"
      };

      const globalOptions = {
        scope: "read:messages",
        audience: "https://read-api.example.com"
      };

      const accessTokens = [
        {
          accessToken: "<my_access_token_1>",
          expiresAt: Date.now() / 1000 + 7200,
          scope: "a",
          requestedScope: "a b",
          audience: "https://api.example.com"
        },
        {
          accessToken: "<my_access_token_2>",
          expiresAt: Date.now() / 1000 + 7200,
          scope: "scope-1",
          audience: "https://api.example.com"
        }
      ];

      const session = createSessionData({ accessTokens });

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
      ).toEqual({
        tokenSet: {
          ...session.tokenSet,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken
        },
        accessTokens: [
          {
            accessToken: tokenSet.accessToken,
            expiresAt: tokenSet.expiresAt,
            scope: "a",
            requestedScope: "a b c",
            audience: "https://api.example.com"
          },
          accessTokens[1]
        ]
      });
    });

    it("should get the sessionChanges when audience is provided, but no scope is provided and no global scope is available", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200,
        audience: "https://api.example.com"
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, {})
      ).toEqual({
        tokenSet: {
          ...session.tokenSet,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken
        },
        accessTokens: [
          {
            accessToken: tokenSet.accessToken,
            audience: "https://api.example.com",
            scope: undefined,
            expiresAt: tokenSet.expiresAt
          }
        ]
      });
    });

    it("should get the sessionChanges when scope and audience are not provided but available as global", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200
      };

      const globalOptions = {
        scope: "read:messages",
        audience: "https://api.example.com"
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
      ).toEqual({
        tokenSet: {
          accessToken: tokenSet.accessToken,
          expiresAt: tokenSet.expiresAt,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken
        }
      });
    });

    it("should get the sessionChanges when access token entry found but access token is different", () => {
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200,
        scope: "read:messages write:messages",
        requestedScope: "read:messages write:messages",
        audience: "https://api.example.com"
      };

      const globalOptions = {
        scope: "read:messages",
        audience: "https://api.example.com"
      };

      const accessTokens = [
        {
          accessToken: "<my_access_token>",
          scope: "read:messages write:messages",
          requestedScope: "read:messages write:messages",
          expiresAt: Date.now() / 1000 + 3600,
          audience: "https://api.example.com"
        },
        {
          accessToken: "<my_other_access_token>",
          scope: "read:projects",
          requestedScope: "read:projects",
          expiresAt: Date.now() / 1000 + 3600,
          audience: "https://api.example.com"
        }
      ];

      const session = createSessionData({ accessTokens });

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
      ).toEqual({
        tokenSet: {
          accessToken: session.tokenSet.accessToken,
          expiresAt: session.tokenSet.expiresAt,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken
        },
        accessTokens: [
          {
            accessToken: tokenSet.accessToken,
            scope: tokenSet.scope,
            requestedScope: tokenSet.requestedScope,
            expiresAt: tokenSet.expiresAt,
            audience: "https://api.example.com"
          },
          accessTokens[1]
        ]
      });
    });

    describe("no session changes cases", () => {
      it("should return undefined when global audience/scope tokenSet has no changes", () => {
        const expiresAt = Date.now() / 1000 + 3600;
        const session = createSessionData({
          tokenSet: {
            accessToken: "<my_access_token>",
            expiresAt,
            refreshToken: "<my_refresh_token>",
            idToken: "<my_id_token>"
          }
        });

        const tokenSet = {
          accessToken: "<my_access_token>",
          expiresAt,
          refreshToken: "<my_refresh_token>",
          idToken: "<my_id_token>"
        };

        const globalOptions = {
          scope: "read:messages",
          audience: "https://api.example.com"
        };

        expect(
          getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
        ).toBeUndefined();
      });

      it("should return undefined when existing access token is the same", () => {
        const tokenSet = {
          accessToken: "<my_access_token>",
          idToken: "<my_new_id_token>",
          refreshToken: "<my_new_refresh_token>",
          expiresAt: Date.now() / 1000 + 7200,
          scope: "write:messages",
          requestedScope: "write:messages",
          audience: "https://api.example.com"
        };

        const globalOptions = {
          scope: "read:messages",
          audience: "https://read-api.example.com"
        };

        const accessTokens = [
          {
            accessToken: "<my_access_token>", // Same access token
            scope: "write:messages",
            requestedScope: "write:messages",
            expiresAt: Date.now() / 1000 + 3600,
            audience: "https://api.example.com"
          }
        ];

        const session = createSessionData({ accessTokens });

        expect(
          getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
        ).toBeUndefined();
      });

      it("should return undefined when there is no audience for specific access token", () => {
        const session = createSessionData();
        const tokenSet = {
          accessToken: "<my_new_access_token>",
          idToken: "<my_new_id_token>",
          refreshToken: "<my_new_refresh_token>",
          expiresAt: Date.now() / 1000 + 7200,
          scope: "write:messages",
          requestedScope: "write:messages"
          // No audience
        };

        const globalOptions = {
          scope: "read:messages"
          // No audience
        };

        expect(
          getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
        ).toBeUndefined();
      });

      it("should return undefined when tokenSet matches global scope from session", () => {
        const expiresAt = Date.now() / 1000 + 3600;
        const session = createSessionData({
          tokenSet: {
            accessToken: "<my_access_token>",
            expiresAt,
            refreshToken: "<my_refresh_token>",
            scope: "read:messages",
            requestedScope: "read:messages"
          }
        });

        const tokenSet = {
          accessToken: "<my_access_token>",
          expiresAt,
          refreshToken: "<my_refresh_token>",
          scope: "read:messages",
          requestedScope: "read:messages"
        };

        const globalOptions = {
          scope: "read:messages"
        };

        expect(
          getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
        ).toBeUndefined();
      });

      it("should return undefined when access token in accessTokens array is identical", () => {
        const accessToken = "<my_access_token>";
        const expiresAt = Date.now() / 1000 + 7200;

        const accessTokens = [
          {
            accessToken,
            scope: "write:messages delete:messages",
            requestedScope: "write:messages delete:messages",
            expiresAt,
            audience: "https://api.example.com"
          },
          {
            accessToken: "<other_access_token>",
            scope: "read:projects",
            requestedScope: "read:projects",
            expiresAt,
            audience: "https://other-api.example.com"
          }
        ];

        const session = createSessionData({ accessTokens });

        const tokenSet = {
          accessToken, // Same token
          idToken: "<my_id_token>",
          refreshToken: "<my_refresh_token>",
          expiresAt,
          scope: "write:messages delete:messages",
          requestedScope: "write:messages delete:messages",
          audience: "https://api.example.com"
        };

        const globalOptions = {
          scope: "read:messages",
          audience: "https://global-api.example.com"
        };

        expect(
          getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
        ).toBeUndefined();
      });

      it("should return undefined when no audience and scope provided with no global options", () => {
        const accessToken = "<my_access_token>";
        const expiresAt = Date.now() / 1000 + 3600;

        const session = createSessionData({
          tokenSet: {
            accessToken,
            expiresAt,
            refreshToken: "<my_refresh_token>"
          }
        });

        const tokenSet = {
          accessToken, // Same token
          expiresAt,
          refreshToken: "<my_refresh_token>"
          // No idToken, so no changes
        };

        const globalOptions = {};

        expect(
          getSessionChangesAfterGetAccessToken(session, tokenSet, globalOptions)
        ).toBeUndefined();
      });
    });
  });
});
