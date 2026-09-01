import { NextRequest } from "next/server.js";
import * as jose from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { generateSecret } from "../../test-fixtures/utils.js";
import { CookieOptions, SessionData } from "../../types/index.js";
import {
  decrypt,
  encrypt,
  RequestCookies,
  ResponseCookies
} from "../cookies/index.js";
import * as cookies from "../cookies/index.js";
import { LEGACY_COOKIE_NAME, LegacySession } from "./normalize-session.js";
import { StatelessSessionStore } from "./stateless-session-store.js";

describe("Stateless Session Store", async () => {
  const baseCookieOptions: CookieOptions = {
    path: "/",
    httpOnly: true,
    sameSite: "lax",
    secure: false
  };

  describe("shouldRollSession", async () => {
    const buildRequest = () =>
      new NextRequest("https://example.com/dashboard", { method: "GET" });

    it("should roll the session when no beforeSessionRolled hook is configured", async () => {
      const secret = await generateSecret(32);
      const sessionStore = new StatelessSessionStore({ secret });

      expect(await sessionStore.shouldRollSession(buildRequest())).toBe(true);
    });

    it("should not roll the session when rolling is disabled", async () => {
      const secret = await generateSecret(32);
      const sessionStore = new StatelessSessionStore({
        secret,
        rolling: false,
        beforeSessionRolled: () => true
      });

      expect(await sessionStore.shouldRollSession(buildRequest())).toBe(false);
    });

    it("should defer to the hook return value", async () => {
      const secret = await generateSecret(32);
      const rollingStore = new StatelessSessionStore({
        secret,
        beforeSessionRolled: () => true
      });
      const nonRollingStore = new StatelessSessionStore({
        secret,
        beforeSessionRolled: () => false
      });

      expect(await rollingStore.shouldRollSession(buildRequest())).toBe(true);
      expect(await nonRollingStore.shouldRollSession(buildRequest())).toBe(
        false
      );
    });

    it("should await an async hook and defer to its resolved value", async () => {
      const secret = await generateSecret(32);
      const rollingStore = new StatelessSessionStore({
        secret,
        beforeSessionRolled: async () => true
      });
      const nonRollingStore = new StatelessSessionStore({
        secret,
        beforeSessionRolled: async () => false
      });

      expect(await rollingStore.shouldRollSession(buildRequest())).toBe(true);
      expect(await nonRollingStore.shouldRollSession(buildRequest())).toBe(
        false
      );
    });

    it("should pass the request to the hook", async () => {
      const secret = await generateSecret(32);
      const beforeSessionRolled = vi.fn().mockReturnValue(false);
      const sessionStore = new StatelessSessionStore({
        secret,
        beforeSessionRolled
      });
      const req = buildRequest();

      await sessionStore.shouldRollSession(req);

      expect(beforeSessionRolled).toHaveBeenCalledWith(req);
    });

    it("should fail open and roll the session when the hook throws", async () => {
      const secret = await generateSecret(32);
      const consoleWarnSpy = vi
        .spyOn(console, "warn")
        .mockImplementation(() => {});
      try {
        const sessionStore = new StatelessSessionStore({
          secret,
          beforeSessionRolled: () => {
            throw new Error("hook failure");
          }
        });

        expect(await sessionStore.shouldRollSession(buildRequest())).toBe(true);
        expect(consoleWarnSpy).toHaveBeenCalled();
      } finally {
        consoleWarnSpy.mockRestore();
      }
    });

    it("should fail open and roll the session when an async hook rejects", async () => {
      const secret = await generateSecret(32);
      const consoleWarnSpy = vi
        .spyOn(console, "warn")
        .mockImplementation(() => {});
      try {
        const sessionStore = new StatelessSessionStore({
          secret,
          beforeSessionRolled: async () => {
            throw new Error("async hook failure");
          }
        });

        expect(await sessionStore.shouldRollSession(buildRequest())).toBe(true);
        expect(consoleWarnSpy).toHaveBeenCalled();
      } finally {
        consoleWarnSpy.mockRestore();
      }
    });
  });

  describe("get", async () => {
    it("should return the decrypted session cookie if it exists", async () => {
      const secret = await generateSecret(32);
      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encryptedCookieValue = await encrypt(session, secret, expiration);

      const headers = new Headers();
      headers.append("cookie", `__session=${encryptedCookieValue}`);
      const requestCookies = new RequestCookies(headers);

      const sessionStore = new StatelessSessionStore({
        secret
      });

      expect(await sessionStore.get(requestCookies)).toEqual(
        expect.objectContaining(session)
      );
    });

    it("should return null if no session cookie exists", async () => {
      const secret = await generateSecret(32);
      const headers = new Headers();
      const requestCookies = new RequestCookies(headers);

      const sessionStore = new StatelessSessionStore({
        secret
      });

      expect(await sessionStore.get(requestCookies)).toBeNull();
    });

    describe("migrate legacy session", async () => {
      it("should convert the legacy session to the new format", async () => {
        const secret = await generateSecret(32);
        const legacySession: LegacySession = {
          user: {
            sub: "user_123",
            sid: "auth0-sid"
          },
          idToken: "idt_123",
          accessToken: "at_123",
          accessTokenScope: "openid profile email",
          refreshToken: "rt_123",
          accessTokenExpiresAt: 123456
        };
        const legacyHeader = {
          iat: Math.floor(Date.now() / 1000),
          uat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000)
        };
        const maxAge = 60 * 60; // 1 hour in seconds
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const encryptedCookieValue = await encrypt(
          legacySession,
          secret,
          expiration,
          legacyHeader
        );

        const headers = new Headers();
        headers.append("cookie", `appSession=${encryptedCookieValue}`);
        const requestCookies = new RequestCookies(headers);

        const sessionStore = new StatelessSessionStore({
          secret
        });

        expect(await sessionStore.get(requestCookies)).toEqual({
          user: { sub: "user_123", sid: "auth0-sid" },
          tokenSet: {
            idToken: "idt_123",
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456,
            scope: "openid profile email"
          },
          internal: {
            sid: "auth0-sid",
            createdAt: legacyHeader.iat
          }
        });
      });

      it("should discard any missing properties", async () => {
        const secret = await generateSecret(32);
        const legacySession: LegacySession = {
          user: {
            sub: "user_123"
          }
        };
        const legacyHeader = {
          iat: Math.floor(Date.now() / 1000),
          uat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000)
        };
        const maxAge = 60 * 60; // 1 hour in seconds
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const encryptedCookieValue = await encrypt(
          legacySession,
          secret,
          expiration,
          legacyHeader
        );

        const headers = new Headers();
        headers.append("cookie", `appSession=${encryptedCookieValue}`);
        const requestCookies = new RequestCookies(headers);

        const sessionStore = new StatelessSessionStore({
          secret
        });

        expect(await sessionStore.get(requestCookies)).toEqual({
          user: { sub: "user_123" },
          tokenSet: {
            expiresAt: undefined,
            accessToken: undefined,
            refreshToken: undefined,
            scope: undefined
          },
          internal: {
            sid: undefined,
            createdAt: legacyHeader.iat
          }
        });
      });

      it("should convert legacy sessions with custom cookie names", async () => {
        const cookieName = "custom-session";
        const secret = await generateSecret(32);
        const legacySession: LegacySession = {
          user: {
            sub: "user_123",
            sid: "auth0-sid"
          },
          idToken: "idt_123",
          accessToken: "at_123",
          accessTokenScope: "openid profile email",
          refreshToken: "rt_123",
          accessTokenExpiresAt: 123456
        };
        const legacyHeader = {
          iat: Math.floor(Date.now() / 1000),
          uat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000)
        };
        const maxAge = 60 * 60; // 1 hour in seconds
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const encryptedCookieValue = await encrypt(
          legacySession,
          secret,
          expiration,
          legacyHeader
        );

        const headers = new Headers();
        headers.append("cookie", `${cookieName}=${encryptedCookieValue}`);
        const requestCookies = new RequestCookies(headers);

        const sessionStore = new StatelessSessionStore({
          secret,
          cookieOptions: {
            name: cookieName
          }
        });

        expect(await sessionStore.get(requestCookies)).toEqual({
          user: { sub: "user_123", sid: "auth0-sid" },
          tokenSet: {
            idToken: "idt_123",
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456,
            scope: "openid profile email"
          },
          internal: {
            sid: "auth0-sid",
            createdAt: legacyHeader.iat
          }
        });
      });
    });
    it("should return the decrypted session cookie if it exists with connection", async () => {
      const secret = await generateSecret(32);
      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      const googleConnectionTokenSet = {
        connection: "google-oauth",
        accessToken: "google-at-123",
        expiresAt: 123456
      };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encryptedCookieValue = await encrypt(session, secret, expiration);
      const encryptedGoogleConnectionCookieValue = await encrypt(
        googleConnectionTokenSet,
        secret,
        expiration
      );

      const headers = new Headers();
      headers.append(
        "cookie",
        `__session=${encryptedCookieValue};__FC_0=${encryptedGoogleConnectionCookieValue}`
      );
      const requestCookies = new RequestCookies(headers);

      const sessionStore = new StatelessSessionStore({
        secret
      });

      const result = await sessionStore.get(requestCookies);

      expect(result).toEqual(expect.objectContaining(session));
      expect(result?.connectionTokenSets).toEqual([
        expect.objectContaining(googleConnectionTokenSet)
      ]);
    });

    it("should return the decrypted session cookie if it exists and exclude a connection when the JWE is expired", async () => {
      const secret = await generateSecret(32);
      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      const googleConnectionTokenSet = {
        connection: "google-oauth",
        accessToken: "google-at-123",
        expiresAt: 123456
      };
      const githubConnectionTokenSet = {
        connection: "github",
        accessToken: "github-at-123",
        expiresAt: 123456
      };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encryptedCookieValue = await encrypt(session, secret, expiration);
      const encryptedGoogleConnectionCookieValue = await encrypt(
        googleConnectionTokenSet,
        secret,
        Math.floor(Date.now() / 1000 - 20)
      ); // expired
      const encryptedGithubConnectionCookieValue = await encrypt(
        githubConnectionTokenSet,
        secret,
        expiration
      );

      const headers = new Headers();
      headers.append(
        "cookie",
        `__session=${encryptedCookieValue};__FC_0=${encryptedGoogleConnectionCookieValue};__FC_1=${encryptedGithubConnectionCookieValue}`
      );
      const requestCookies = new RequestCookies(headers);

      const sessionStore = new StatelessSessionStore({
        secret
      });

      const result = await sessionStore.get(requestCookies);

      expect(result).toEqual(expect.objectContaining(session));
      expect(result?.connectionTokenSets).toEqual([
        expect.objectContaining(githubConnectionTokenSet)
      ]);
    });
  });

  describe("set", async () => {
    describe("with rolling sessions enabled", async () => {
      beforeEach(() => {
        vi.useFakeTimers();
      });

      afterEach(() => {
        vi.restoreAllMocks();
      });

      it("should extend the cookie lifetime by the inactivity duration", async () => {
        const currentTime = Date.now();
        const createdAt = Math.floor(currentTime / 1000);
        const secret = await generateSecret(32);
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
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800
        });

        vi.setSystemTime(currentTime + 10 * 60 * 1000);

        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");

        expect(cookie).toBeDefined();
        expect(
          ((await decrypt(cookie!.value, secret)) as jose.JWTDecryptResult)
            .payload
        ).toEqual(expect.objectContaining(session));
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("lax");
        expect(cookie?.maxAge).toEqual(1800);
        expect(cookie?.secure).toEqual(false);
      });

      it("should not exceed the absolute timeout duration", async () => {
        const currentTime = Date.now();
        const createdAt = Math.floor(currentTime / 1000);
        const secret = await generateSecret(32);
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
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800
        });

        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");

        expect(cookie).toBeDefined();

        vi.setSystemTime(currentTime + 35 * 60 * 1000);

        const decryptedSession = await decrypt(cookie!.value, secret);
        expect(decryptedSession).toEqual(null);
      });

      it("should delete the legacy cookie if it exists", async () => {
        const currentTime = Date.now();
        const createdAt = Math.floor(currentTime / 1000);
        const secret = await generateSecret(32);
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
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatelessSessionStore({
          secret
        });

        vi.spyOn(responseCookies, "set");

        // Mock getChunkedCookie to simulate existing legacy cookie
        vi.spyOn(cookies, "getChunkedCookie").mockImplementation((name) => {
          if (name === LEGACY_COOKIE_NAME) {
            return "legacy_session_data"; // Simulate existing legacy cookie
          }
          return undefined;
        });

        await sessionStore.set(requestCookies, responseCookies, session);

        expect(responseCookies.set).toHaveBeenCalledWith(
          LEGACY_COOKIE_NAME,
          "",
          {
            httpOnly: true,
            maxAge: 0,
            path: "/",
            sameSite: "lax",
            secure: false
          }
        );
      });

      it("should delete the legacy cookie chunks if they exists", async () => {
        const currentTime = Date.now();
        const createdAt = Math.floor(currentTime / 1000);
        const secret = await generateSecret(32);
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
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatelessSessionStore({
          secret
        });

        vi.spyOn(responseCookies, "set");

        // Mock getChunkedCookie to simulate existing legacy cookie
        vi.spyOn(cookies, "getChunkedCookie").mockImplementation((name) => {
          if (name === LEGACY_COOKIE_NAME) {
            return "legacy_chunked_session_data"; // Simulate existing legacy cookie
          }
          return undefined;
        });

        vi.spyOn(requestCookies, "getAll").mockReturnValue([
          { name: `${LEGACY_COOKIE_NAME}.0`, value: "" },
          { name: `${LEGACY_COOKIE_NAME}.1`, value: "" }
        ]);

        await sessionStore.set(requestCookies, responseCookies, session);

        // setChunkedCookie for __session now makes 6 calls (1 set + 5 deletes of __session__0..4)
        // Then legacy cookie deletion: 1 base + 2 legacy chunks = 3
        // Total: 6 + 1 + 2 = 9 calls
        expect(responseCookies.set).toHaveBeenCalledTimes(9);
        // Verify main __session cookie is set (without maxAge: 0)
        expect(responseCookies.set).toHaveBeenCalledWith(
          "__session",
          expect.any(String),
          expect.not.objectContaining({ maxAge: 0 })
        );
        // Verify deterministic deletes of __session__0..4
        expect(responseCookies.set).toHaveBeenCalledWith(
          `__session__0`,
          "",
          expect.objectContaining({ maxAge: 0 })
        );
        expect(responseCookies.set).toHaveBeenCalledWith(
          `__session__1`,
          "",
          expect.objectContaining({ maxAge: 0 })
        );
        expect(responseCookies.set).toHaveBeenCalledWith(
          `__session__2`,
          "",
          expect.objectContaining({ maxAge: 0 })
        );
        expect(responseCookies.set).toHaveBeenCalledWith(
          `__session__3`,
          "",
          expect.objectContaining({ maxAge: 0 })
        );
        expect(responseCookies.set).toHaveBeenCalledWith(
          `__session__4`,
          "",
          expect.objectContaining({ maxAge: 0 })
        );
        // Verify legacy cookie base is deleted
        expect(responseCookies.set).toHaveBeenCalledWith(
          LEGACY_COOKIE_NAME,
          "",
          {
            httpOnly: true,
            maxAge: 0,
            path: "/",
            sameSite: "lax",
            secure: false
          }
        );
        // Verify legacy chunks .0 and .1 are deleted
        expect(responseCookies.set).toHaveBeenCalledWith(
          `${LEGACY_COOKIE_NAME}.0`,
          "",
          {
            httpOnly: true,
            maxAge: 0,
            path: "/",
            sameSite: "lax",
            secure: false
          }
        );
        expect(responseCookies.set).toHaveBeenCalledWith(
          `${LEGACY_COOKIE_NAME}.1`,
          "",
          {
            httpOnly: true,
            maxAge: 0,
            path: "/",
            sameSite: "lax",
            secure: false
          }
        );
      });
    });

    describe("with rolling sessions disabled", async () => {
      it("should set the cookie with a maxAge of the absolute session duration", async () => {
        const secret = await generateSecret(32);
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456
          },
          internal: {
            sid: "auth0-sid",
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: false,
          absoluteDuration: 3600
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");

        expect(cookie).toBeDefined();
        expect(
          ((await decrypt(cookie!.value, secret)) as jose.JWTDecryptResult)
            .payload
        ).toEqual(expect.objectContaining(session));
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("lax");
        expect(cookie?.maxAge).toEqual(3600);
        expect(cookie?.secure).toEqual(false);
      });
    });

    describe("with cookieOptions", async () => {
      it("should apply the secure attribute to the cookie", async () => {
        const secret = await generateSecret(32);
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456
          },
          internal: {
            sid: "auth0-sid",
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: false,
          absoluteDuration: 3600,
          cookieOptions: {
            secure: true
          }
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");

        expect(cookie).toBeDefined();
        expect(
          ((await decrypt(cookie!.value, secret)) as jose.JWTDecryptResult)
            .payload
        ).toEqual(expect.objectContaining(session));
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("lax");
        expect(cookie?.maxAge).toEqual(3600);
        expect(cookie?.secure).toEqual(true);
      });

      it("should apply the sameSite attribute to the cookie", async () => {
        const secret = await generateSecret(32);
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456
          },
          internal: {
            sid: "auth0-sid",
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: false,
          absoluteDuration: 3600,
          cookieOptions: {
            secure: true,
            sameSite: "strict"
          }
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");

        expect(cookie).toBeDefined();
        expect(
          ((await decrypt(cookie!.value, secret)) as jose.JWTDecryptResult)
            .payload
        ).toEqual(expect.objectContaining(session));
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("strict");
        expect(cookie?.maxAge).toEqual(3600);
        expect(cookie?.secure).toEqual(true);
      });

      it("should apply the path to the cookie", async () => {
        const secret = await generateSecret(32);
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456
          },
          internal: {
            sid: "auth0-sid",
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatelessSessionStore({
          secret,
          cookieOptions: {
            path: "/custom-path"
          }
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");

        expect(cookie).toBeDefined();
        expect(
          ((await decrypt(cookie!.value, secret)) as jose.JWTDecryptResult)
            .payload
        ).toEqual(expect.objectContaining(session));
        expect(cookie?.path).toEqual("/custom-path");
      });

      it("should apply the cookie name", async () => {
        const secret = await generateSecret(32);
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456
          },
          internal: {
            sid: "auth0-sid",
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatelessSessionStore({
          secret,
          rolling: false,
          absoluteDuration: 3600,
          cookieOptions: {
            secure: true,
            name: "custom-session"
          }
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("custom-session");

        expect(cookie).toBeDefined();
        expect(
          ((await decrypt(cookie!.value, secret)) as jose.JWTDecryptResult)
            .payload
        ).toEqual(expect.objectContaining(session));
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("lax");
        expect(cookie?.maxAge).toEqual(3600);
        expect(cookie?.secure).toEqual(true);
      });
    });

    it("should set new cookie and delete legacy cookie when the legacy cookie exists (chunked)", async () => {
      const secret = await generateSecret(32);
      const sessionToSet: SessionData = {
        user: { sub: "user_to_set" },
        tokenSet: { accessToken: "set_at", expiresAt: 300 },
        internal: { sid: "set_sid", createdAt: Math.floor(Date.now() / 1000) }
      };
      const dummyLegacySession: LegacySession = {
        user: { sub: "legacy_user_dummy" }
      };
      const maxAge = 300; // 5 minutes in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encryptedLegacyValue = await encrypt(
        dummyLegacySession,
        secret,
        expiration
      );

      const tempResCookies = new ResponseCookies(new Headers());
      cookies.setChunkedCookie(
        LEGACY_COOKIE_NAME,
        encryptedLegacyValue,
        baseCookieOptions,
        new RequestCookies(new Headers()),
        tempResCookies
      );
      const finalHeaders = new Headers();
      const legacyCookiesInSetup = tempResCookies.getAll();
      legacyCookiesInSetup.forEach((cookie) =>
        finalHeaders.append(
          "cookie",
          `${cookie.name}=${encodeURIComponent(cookie.value)}`
        )
      );
      const requestCookies = new RequestCookies(finalHeaders);

      const responseCookies = new ResponseCookies(new Headers());
      const setSpy = vi.spyOn(responseCookies, "set");
      const sessionStore = new StatelessSessionStore({ secret });

      await sessionStore.set(requestCookies, responseCookies, sessionToSet);

      const setCookies = responseCookies.getAll();
      let reconstructedValue = "";
      const baseCookie = setCookies.find((c) => c.name === "__session");
      if (baseCookie) {
        reconstructedValue = baseCookie.value;
        let i = 0;
        let chunkCookie;
        while (
          (chunkCookie = setCookies.find((c) => c.name === `__session.${i}`))
        ) {
          reconstructedValue += chunkCookie.value;
          i++;
        }
      }

      expect(reconstructedValue).not.toBe("");
      const decryptedNewSession = await decrypt<SessionData>(
        reconstructedValue!,
        secret
      );
      const decryptedPayload = decryptedNewSession!.payload;
      expect(decryptedPayload).toEqual(expect.objectContaining(sessionToSet));

      // setChunkedCookie for __session makes 6 calls (1 set + 5 deletes of __session__0..4)
      // legacyCookiesInSetup will have entries from setChunkedCookie on the legacy cookie
      // For a chunked legacy cookie, it would be: 3 sets + 2 deletes + 1 base delete = 6 calls in setup
      // But those were on tempResCookies. In sessionStore.set, we have:
      // - 6 calls for __session from setChunkedCookie
      // - 1 call for deleting legacy cookie base
      // Total: 7 calls
      expect(setSpy).toHaveBeenCalledTimes(7);

      // Verify main __session cookie is set
      expect(setSpy).toHaveBeenCalledWith(
        "__session",
        expect.any(String),
        expect.not.objectContaining({ maxAge: 0 })
      );

      // Verify legacy cookie base is deleted
      expect(setSpy).toHaveBeenCalledWith(LEGACY_COOKIE_NAME, "", {
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: false
      });
    });

    describe("session cookie size warning", async () => {
      const baseSession = (createdAt: number): SessionData => ({
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456
        },
        internal: { sid: "auth0-sid", createdAt }
      });

      it("warns when the session cookie exceeds the size threshold", async () => {
        const secret = await generateSecret(32);
        const consoleWarnSpy = vi
          .spyOn(console, "warn")
          .mockImplementation(() => {});
        try {
          const session = baseSession(Math.floor(Date.now() / 1000));
          // Large custom claim pushes the encoded session well past 4096 bytes
          // (and across multiple __session chunks).
          (session.user as Record<string, unknown>).bigClaim = "x".repeat(6000);

          const sessionStore = new StatelessSessionStore({ secret });
          await sessionStore.set(
            new RequestCookies(new Headers()),
            new ResponseCookies(new Headers()),
            session
          );

          const warned = consoleWarnSpy.mock.calls.some((c) =>
            String(c[0]).includes("__session cookie size")
          );
          expect(warned).toBe(true);
        } finally {
          consoleWarnSpy.mockRestore();
        }
      });

      it("does not warn for a small session cookie", async () => {
        const secret = await generateSecret(32);
        const consoleWarnSpy = vi
          .spyOn(console, "warn")
          .mockImplementation(() => {});
        try {
          const sessionStore = new StatelessSessionStore({ secret });
          await sessionStore.set(
            new RequestCookies(new Headers()),
            new ResponseCookies(new Headers()),
            baseSession(Math.floor(Date.now() / 1000))
          );

          const warned = consoleWarnSpy.mock.calls.some((c) =>
            String(c[0]).includes("__session cookie size")
          );
          expect(warned).toBe(false);
        } finally {
          consoleWarnSpy.mockRestore();
        }
      });
    });
  });

  describe("set — connection token sets (__FC_N cookies)", async () => {
    const baseSession = (createdAt: number): SessionData => ({
      user: { sub: "user_123" },
      tokenSet: {
        accessToken: "at_123",
        refreshToken: "rt_123",
        expiresAt: 9999999999
      },
      internal: { sid: "sid", createdAt }
    });

    it("writes one __FC_N cookie per connection token set", async () => {
      const secret = await generateSecret(32);
      const session: SessionData = {
        ...baseSession(Math.floor(Date.now() / 1000)),
        connectionTokenSets: [
          {
            connection: "google-oauth2",
            accessToken: "fc_g",
            expiresAt: 9999999999
          },
          { connection: "github", accessToken: "fc_gh", expiresAt: 9999999999 }
        ]
      };
      const reqCookies = new RequestCookies(new Headers());
      const resCookies = new ResponseCookies(new Headers());
      const store = new StatelessSessionStore({ secret });

      await store.set(reqCookies, resCookies, session);

      expect(resCookies.get("__FC_0")?.value).toBeTruthy();
      expect(resCookies.get("__FC_1")?.value).toBeTruthy();
      // Session cookie must not contain the connectionTokenSets payload.
      expect(resCookies.get("__FC_2")).toBeUndefined();
    });

    it("round-trips: get() reads back what set() wrote", async () => {
      const secret = await generateSecret(32);
      const createdAt = Math.floor(Date.now() / 1000);
      const googleTokenSet = {
        connection: "google-oauth2",
        accessToken: "fc_g",
        expiresAt: 9999999999
      };
      const session: SessionData = {
        ...baseSession(createdAt),
        connectionTokenSets: [googleTokenSet]
      };
      const reqCookies = new RequestCookies(new Headers());
      const resCookies = new ResponseCookies(new Headers());
      const store = new StatelessSessionStore({ secret });

      await store.set(reqCookies, resCookies, session);

      // Promote the response cookies into the next request's cookies.
      const nextHeaders = new Headers();
      resCookies
        .getAll()
        .filter((c) => (c.maxAge ?? 1) > 0)
        .forEach((c) => nextHeaders.append("cookie", `${c.name}=${c.value}`));
      const nextReqCookies = new RequestCookies(nextHeaders);

      const result = await store.get(nextReqCookies);
      expect(result?.connectionTokenSets).toEqual([
        expect.objectContaining(googleTokenSet)
      ]);
    });

    it("does not write __FC_N cookies when connectionTokenSets is absent", async () => {
      const secret = await generateSecret(32);
      const session: SessionData = baseSession(Math.floor(Date.now() / 1000));
      const reqCookies = new RequestCookies(new Headers());
      const resCookies = new ResponseCookies(new Headers());
      const store = new StatelessSessionStore({ secret });

      await store.set(reqCookies, resCookies, session);

      const fcCookies = resCookies
        .getAll()
        .filter((c) => c.name.startsWith("__FC_"));
      expect(fcCookies).toHaveLength(0);
    });

    it("warns when an individual __FC_N cookie exceeds 4096 bytes", async () => {
      const secret = await generateSecret(32);
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      try {
        const session: SessionData = {
          ...baseSession(Math.floor(Date.now() / 1000)),
          connectionTokenSets: [
            // A 4000-char accessToken produces a JWE well over 4096 encoded bytes.
            {
              connection: "google-oauth2",
              accessToken: "x".repeat(4000),
              expiresAt: 9999999999
            }
          ]
        };
        const store = new StatelessSessionStore({ secret });
        await store.set(
          new RequestCookies(new Headers()),
          new ResponseCookies(new Headers()),
          session
        );

        const warned = warnSpy.mock.calls.some((c) =>
          String(c[0]).includes("__FC_0 cookie size exceeds")
        );
        expect(warned).toBe(true);
      } finally {
        warnSpy.mockRestore();
      }
    });
  });

  describe("set — session size warning emitted only once per process", async () => {
    it("warns on the first oversized set() and suppresses the second", async () => {
      // Reset the module-level flag by re-importing a fresh module instance.
      vi.resetModules();
      const { StatelessSessionStore: FreshStore } =
        await import("./stateless-session-store.js");
      const secret = await generateSecret(32);
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      try {
        const store = new FreshStore({ secret });
        const bigSession = (createdAt: number): SessionData => {
          const s: SessionData = {
            user: { sub: "user_123" },
            tokenSet: { accessToken: "at", expiresAt: 9999999999 },
            internal: { sid: "sid", createdAt }
          };
          (s.user as Record<string, unknown>).bigClaim = "x".repeat(6000);
          return s;
        };

        await store.set(
          new RequestCookies(new Headers()),
          new ResponseCookies(new Headers()),
          bigSession(Math.floor(Date.now() / 1000))
        );
        await store.set(
          new RequestCookies(new Headers()),
          new ResponseCookies(new Headers()),
          bigSession(Math.floor(Date.now() / 1000))
        );

        const sessionSizeWarns = warnSpy.mock.calls.filter((c) =>
          String(c[0]).includes("cookie size")
        );
        expect(sessionSizeWarns).toHaveLength(1);
      } finally {
        warnSpy.mockRestore();
        vi.resetModules();
      }
    });
  });

  describe("get — corrupted __FC cookie is silently skipped", async () => {
    it("excludes an __FC cookie whose JWE cannot be decrypted", async () => {
      const secret = await generateSecret(32);
      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: { accessToken: "at_123", expiresAt: 9999999999 },
        internal: { sid: "sid", createdAt: Math.floor(Date.now() / 1000) }
      };
      const expiration = Math.floor(Date.now() / 1000 + 3600);
      const validJwe = await encrypt(session, secret, expiration);

      const headers = new Headers();
      headers.append("cookie", `__session=${validJwe};__FC_0=not-a-valid-jwe`);
      const reqCookies = new RequestCookies(headers);
      const store = new StatelessSessionStore({ secret });

      const result = await store.get(reqCookies);

      // Session itself is intact; the bad FC cookie is dropped, not throwing.
      expect(result?.user.sub).toBe("user_123");
      expect(result?.connectionTokenSets).toBeUndefined();
    });
  });

  describe("delete — clears __FC_N connection-token cookies", async () => {
    it("deletes all __FC_N cookies present in the request", async () => {
      const secret = await generateSecret(32);
      const expiration = Math.floor(Date.now() / 1000 + 3600);
      const fakeJwe = await encrypt(
        { connection: "google-oauth2", accessToken: "fc_g", expiresAt: 1 },
        secret,
        expiration
      );

      const headers = new Headers();
      headers.append("cookie", `__FC_0=${fakeJwe};__FC_1=${fakeJwe}`);
      const reqCookies = new RequestCookies(headers);
      const resCookies = new ResponseCookies(new Headers());
      const store = new StatelessSessionStore({ secret });

      await store.delete(reqCookies, resCookies);

      expect(resCookies.get("__FC_0")?.maxAge).toBe(0);
      expect(resCookies.get("__FC_1")?.maxAge).toBe(0);
    });

    describe("__FC connection-token orphan cleanup", async () => {
      const baseSession = (
        connectionTokenSets: SessionData["connectionTokenSets"]
      ): SessionData => ({
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000)
        },
        connectionTokenSets
      });

      // Seeds `count` __FC_i cookies on the request, as a prior write would have.
      async function seedConnectionCookies(
        store: StatelessSessionStore,
        requestCookies: RequestCookies,
        responseCookies: ResponseCookies,
        connections: string[]
      ) {
        await store.set(
          requestCookies,
          responseCookies,
          baseSession(
            connections.map((connection) => ({
              connection,
              accessToken: `at_${connection}`,
              expiresAt: 999999
            }))
          )
        );
      }

      // A `__FC` cookie is "deleted" via `resCookies.set(name, "", {maxAge:0})`,
      // so a deletion is a `set` call with an empty value and `maxAge` 0.
      function deletedCookieNames(setSpy: {
        mock: { calls: unknown[][] };
      }): string[] {
        return setSpy.mock.calls
          .filter(
            (call) =>
              call[1] === "" &&
              typeof call[2] === "object" &&
              call[2] !== null &&
              (call[2] as { maxAge?: number }).maxAge === 0
          )
          .map((call) => call[0] as string);
      }

      it("deletes trailing __FC cookies when the array shrinks", async () => {
        const secret = await generateSecret(32);
        const store = new StatelessSessionStore({ secret });
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        // Start with three connections -> __FC_0, __FC_1, __FC_2
        await seedConnectionCookies(store, requestCookies, responseCookies, [
          "google-oauth2",
          "github",
          "slack"
        ]);
        expect(requestCookies.get("__FC_0")).toBeDefined();
        expect(requestCookies.get("__FC_1")).toBeDefined();
        expect(requestCookies.get("__FC_2")).toBeDefined();

        // Now write a session with a single connection.
        const setSpy = vi.spyOn(responseCookies, "set");
        await store.set(
          requestCookies,
          responseCookies,
          baseSession([
            {
              connection: "google-oauth2",
              accessToken: "at_google-oauth2",
              expiresAt: 999999
            }
          ])
        );

        // __FC_1 and __FC_2 must be deleted; __FC_0 stays (overwritten).
        const deletedNames = deletedCookieNames(setSpy);
        expect(deletedNames).toContain("__FC_1");
        expect(deletedNames).toContain("__FC_2");
        expect(deletedNames).not.toContain("__FC_0");
      });

      it("does not delete any __FC cookies when the array grows", async () => {
        const secret = await generateSecret(32);
        const store = new StatelessSessionStore({ secret });
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        await seedConnectionCookies(store, requestCookies, responseCookies, [
          "google-oauth2"
        ]);

        const setSpy = vi.spyOn(responseCookies, "set");
        await store.set(
          requestCookies,
          responseCookies,
          baseSession([
            {
              connection: "google-oauth2",
              accessToken: "at_google-oauth2",
              expiresAt: 999999
            },
            {
              connection: "github",
              accessToken: "at_github",
              expiresAt: 999999
            }
          ])
        );

        const deletedFcNames = deletedCookieNames(setSpy).filter((name) =>
          name.startsWith("__FC")
        );
        expect(deletedFcNames).toEqual([]);
      });

      it("deletes all __FC cookies when the array becomes empty", async () => {
        const secret = await generateSecret(32);
        const store = new StatelessSessionStore({ secret });
        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        await seedConnectionCookies(store, requestCookies, responseCookies, [
          "google-oauth2",
          "github"
        ]);

        const setSpy = vi.spyOn(responseCookies, "set");
        await store.set(
          requestCookies,
          responseCookies,
          baseSession(undefined)
        );

        const deletedNames = deletedCookieNames(setSpy);
        expect(deletedNames).toContain("__FC_0");
        expect(deletedNames).toContain("__FC_1");
      });

      it("leaves non-indexed __FC-prefixed cookies untouched", async () => {
        const secret = await generateSecret(32);
        const store = new StatelessSessionStore({ secret });

        // A legacy/foreign cookie that does not match the `__FC_<index>` shape.
        const headers = new Headers();
        headers.append("cookie", "__FCcustom=preserve-me");
        const requestCookies = new RequestCookies(headers);
        const responseCookies = new ResponseCookies(new Headers());

        const setSpy = vi.spyOn(responseCookies, "set");
        await store.set(
          requestCookies,
          responseCookies,
          baseSession([
            {
              connection: "google-oauth2",
              accessToken: "at_google-oauth2",
              expiresAt: 999999
            }
          ])
        );

        const deletedNames = deletedCookieNames(setSpy);
        expect(deletedNames).not.toContain("__FCcustom");
      });
    });
  });

  describe("delete", async () => {
    it("should remove the cookie", async () => {
      const secret = await generateSecret(32);
      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const requestCookies = new RequestCookies(new Headers());
      const responseCookies = new ResponseCookies(new Headers());

      const sessionStore = new StatelessSessionStore({
        secret
      });
      await sessionStore.set(requestCookies, responseCookies, session);
      expect(responseCookies.get("__session")).toBeDefined();

      await sessionStore.delete(requestCookies, responseCookies);
      const cookie = responseCookies.get("__session");
      expect(cookie?.value).toEqual("");
      expect(cookie?.maxAge).toEqual(0);
    });

    it("should not throw an error if the cookie does not exist", async () => {
      const secret = await generateSecret(32);
      const requestCookies = new RequestCookies(new Headers());
      const responseCookies = new ResponseCookies(new Headers());
      const sessionStore = new StatelessSessionStore({
        secret
      });

      await expect(
        sessionStore.delete(requestCookies, responseCookies)
      ).resolves.not.toThrow();
    });

    it("should delete the legacy cookie if it exists", async () => {
      const secret = await generateSecret(32);
      const requestCookies = new RequestCookies(new Headers());
      const responseCookies = new ResponseCookies(new Headers());

      const sessionStore = new StatelessSessionStore({
        secret
      });

      vi.spyOn(responseCookies, "set");

      // Mock getChunkedCookie to simulate existing legacy cookie
      vi.spyOn(cookies, "getChunkedCookie").mockImplementation((name) => {
        if (name === LEGACY_COOKIE_NAME) {
          return "legacy_session_data";
        }
        return undefined;
      });

      await sessionStore.delete(requestCookies, responseCookies);

      expect(responseCookies.set).toHaveBeenCalledWith(LEGACY_COOKIE_NAME, "", {
        httpOnly: true,
        maxAge: 0,
        path: "/",
        sameSite: "lax",
        secure: false
      });
    });
  });
});
