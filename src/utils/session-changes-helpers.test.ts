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
    it("should get the sessionChangs when no scope and audience is provided", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200
      };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, {}, {})
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
        getSessionChangesAfterGetAccessToken(session, tokenSet, {}, {})
      ).toBeUndefined();
    });


    it("should get the sessionChanges when scope and audience is provided but are the global values", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200
      };
      const options = { scope: "read:messages", audience: "https://api.example.com" };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, options, options)
      ).toEqual({
        tokenSet: {
          accessToken: tokenSet.accessToken,
          expiresAt: tokenSet.expiresAt,
          idToken: tokenSet.idToken,
          refreshToken: tokenSet.refreshToken
        }
      });
    });

    it("should get the sessionChanges when scope and audience is provided and are not the global values", () => {
      const session = createSessionData();
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200
      };
      const options = { scope: "write:messages", audience: "https://api.example.com" };
      const globalOptions = { scope: "read:messages", audience: "https://read-api.example.com" };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, options, globalOptions)
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
            scope: options.scope,
            audience: options.audience
          }
        ]
      });
    });

    it("should get the sessionChanges when scope and audience is provided, are not the global values and entry already exists", () => {
      const tokenSet = {
        accessToken: "<my_new_access_token>",
        idToken: "<my_new_id_token>",
        refreshToken: "<my_new_refresh_token>",
        expiresAt: Date.now() / 1000 + 7200
      };
      const options = { scope: "write:messages", audience: "https://api.example.com" };
      const session = createSessionData({
        accessTokens: [
          {
            accessToken: '<my_old_access_token>',
            expiresAt: Date.now() / 1000 + 7200,
            scope: options.scope,
            audience: options.audience
          }
        ]
      });
      
      const globalOptions = { scope: "read:messages", audience: "https://read-api.example.com" };

      expect(
        getSessionChangesAfterGetAccessToken(session, tokenSet, options, globalOptions)
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
            scope: options.scope,
            audience: options.audience
          }
        ]
      });
    });
  });
});
