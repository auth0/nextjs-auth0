import * as jose from "jose";
import { describe, expect, it } from "vitest";

import { decrypt } from "../server/cookies";
import { generateSecret } from "../test/utils";
import { SessionData } from "../types";
import {
  generateSessionCookie,
  GenerateSessionCookieConfig
} from "./generate-session-cookie";

describe("generateSessionCookie", async () => {
  it("should use the session data provided", async () => {
    const createdAt = Math.floor(Date.now() / 1000);
    const session: SessionData = {
      user: { sub: "user_123" },
      tokenSet: {
        accessToken: "at_123",
        refreshToken: "rt_123",
        expiresAt: 123456
      },
      internal: {
        sid: "auth0-sid",
        createdAt
      }
    };
    const secret = await generateSecret(32);
    const config: GenerateSessionCookieConfig = {
      secret
    };
    const sessionCookie = await generateSessionCookie(session, config);
    expect(sessionCookie).toEqual(expect.any(String));
    expect((await decrypt(sessionCookie, secret) as jose.JWTDecryptResult).payload).toEqual(expect.objectContaining({
      user: {
        sub: "user_123"
      },
      tokenSet: {
        accessToken: "at_123",
        refreshToken: "rt_123",
        expiresAt: 123456
      },
      internal: {
        sid: "auth0-sid",
        createdAt: createdAt
      }
    }));
  });

  it("should populate the internal property if it was not provided", async () => {
    const session: Partial<SessionData> = {
      user: { sub: "user_123" },
      tokenSet: {
        accessToken: "at_123",
        refreshToken: "rt_123",
        expiresAt: 123456
      }
    };
    const secret = await generateSecret(32);
    const config: GenerateSessionCookieConfig = {
      secret
    };
    const sessionCookie = await generateSessionCookie(session, config);
    expect(sessionCookie).toEqual(expect.any(String));
    expect((await decrypt(sessionCookie, secret) as jose.JWTDecryptResult).payload).toEqual(expect.objectContaining({
      user: {
        sub: "user_123"
      },
      tokenSet: {
        accessToken: "at_123",
        refreshToken: "rt_123",
        expiresAt: 123456
      },
      internal: {
        sid: "auth0-sid",
        createdAt: expect.any(Number)
      }
    }));
  });

  it("should not populate the internal property if a null was provided", async () => {
    const session: Partial<SessionData> = {
      user: { sub: "user_123" },
      tokenSet: {
        accessToken: "at_123",
        refreshToken: "rt_123",
        expiresAt: 123456
      },
      // @ts-expect-error intentionally testing with null (invalid type for internal)
      internal: null
    };
    const secret = await generateSecret(32);
    const config: GenerateSessionCookieConfig = {
      secret
    };
    const sessionCookie = await generateSessionCookie(session, config);
    expect(sessionCookie).toEqual(expect.any(String));
    expect((await decrypt(sessionCookie, secret) as jose.JWTDecryptResult).payload).not.toEqual(expect.objectContaining({
      internal: expect.anything()
    }));
  });

  it("should not populate the internal property if a undefined was provided", async () => {
    const session: Partial<SessionData> = {
      user: { sub: "user_123" },
      tokenSet: {
        accessToken: "at_123",
        refreshToken: "rt_123",
        expiresAt: 123456
      },
      internal: undefined
    };
    const secret = await generateSecret(32);
    const config: GenerateSessionCookieConfig = {
      secret
    };
    const sessionCookie = await generateSessionCookie(session, config);
    expect(sessionCookie).toEqual(expect.any(String));
    expect((await decrypt(sessionCookie, secret) as jose.JWTDecryptResult).payload).not.toEqual(expect.objectContaining({
      internal: expect.anything()
    }));
  });
});
