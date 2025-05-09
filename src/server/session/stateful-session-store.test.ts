import * as jose from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { generateSecret } from "../../test/utils";
import { SessionData } from "../../types";
import {
  decrypt,
  encrypt,
  RequestCookies,
  ResponseCookies,
  sign
} from "../cookies";
import { LEGACY_COOKIE_NAME, LegacySessionPayload } from "./normalize-session";
import { StatefulSessionStore } from "./stateful-session-store";

describe("Stateful Session Store", async () => {
  describe("get", async () => {
    it("should call the store.get method with the session ID", async () => {
      const sessionId = "ses_123";
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
      const store = {
        get: vi.fn().mockResolvedValue(session),
        set: vi.fn(),
        delete: vi.fn()
      };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encryptedCookieValue = await encrypt(
        {
          id: sessionId
        },
        secret,
        expiration,
      );

      const headers = new Headers();
      headers.append("cookie", `__session=${encryptedCookieValue}`);
      const requestCookies = new RequestCookies(headers);

      const sessionStore = new StatefulSessionStore({
        secret,
        store
      });

      const sessionFromDb = await sessionStore.get(requestCookies);
      expect(store.get).toHaveBeenCalledOnce();
      expect(store.get).toHaveBeenCalledWith(sessionId);
      expect(sessionFromDb).toEqual(session);
    });

    it("should return null if no session cookie exists", async () => {
      const secret = await generateSecret(32);
      const headers = new Headers();
      const requestCookies = new RequestCookies(headers);
      const store = {
        get: vi.fn(),
        set: vi.fn(),
        delete: vi.fn()
      };
      const sessionStore = new StatefulSessionStore({
        secret,
        store
      });

      expect(await sessionStore.get(requestCookies)).toBeNull();
    });

    it("should return null if no matching session exists in the DB", async () => {
      const sessionId = "ses_does_not_exist";
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
      const store = {
        get: vi.fn().mockImplementation(async (sessionId: string) => {
          if (sessionId === "ses_123") {
            return session;
          }

          return null;
        }),
        set: vi.fn(),
        delete: vi.fn()
      };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encryptedCookieValue = await encrypt(
        {
          id: sessionId
        },
        secret,
        expiration,
      );

      const headers = new Headers();
      headers.append("cookie", `__session=${encryptedCookieValue}`);
      const requestCookies = new RequestCookies(headers);

      const sessionStore = new StatefulSessionStore({
        secret,
        store
      });

      const sessionFromDb = await sessionStore.get(requestCookies);
      expect(store.get).toHaveBeenCalledOnce();
      expect(store.get).toHaveBeenCalledWith(sessionId);
      expect(sessionFromDb).toBeNull();
    });

    describe("migrate legacy session", async () => {
      it("should convert the legacy session to the new format", async () => {
        const sessionId = "ses_123";
        const secret = await generateSecret(32);
        const legacySession: LegacySessionPayload = {
          header: {
            iat: Math.floor(Date.now() / 1000),
            uat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000)
          },
          data: {
            user: {
              sub: "user_123",
              sid: "auth0-sid"
            },
            accessToken: "at_123",
            accessTokenScope: "openid profile email",
            refreshToken: "rt_123",
            accessTokenExpiresAt: 123456
          }
        };
        const store = {
          get: vi.fn().mockResolvedValue(legacySession),
          set: vi.fn(),
          delete: vi.fn()
        };
        const signedCookieValue = await sign("appSession", sessionId, secret);

        const headers = new Headers();
        headers.append("cookie", `appSession=${signedCookieValue}`);
        const requestCookies = new RequestCookies(headers);

        const sessionStore = new StatefulSessionStore({
          secret,
          store
        });

        const sessionFromDb = await sessionStore.get(requestCookies);
        expect(store.get).toHaveBeenCalledOnce();
        expect(store.get).toHaveBeenCalledWith(sessionId);
        expect(sessionFromDb).toEqual({
          user: { sub: "user_123", sid: "auth0-sid" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456,
            scope: "openid profile email"
          },
          internal: {
            sid: "auth0-sid",
            createdAt: legacySession.header.iat
          }
        });
      });

      it("should discard any missing properties", async () => {
        const sessionId = "ses_123";
        const secret = await generateSecret(32);
        const legacySession: LegacySessionPayload = {
          header: {
            iat: Math.floor(Date.now() / 1000),
            uat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000)
          },
          data: {
            user: {
              sub: "user_123",
              sid: "auth0-sid"
            }
          }
        };
        const store = {
          get: vi.fn().mockResolvedValue(legacySession),
          set: vi.fn(),
          delete: vi.fn()
        };
        const signedCookieValue = await sign("appSession", sessionId, secret);

        const headers = new Headers();
        headers.append("cookie", `appSession=${signedCookieValue}`);
        const requestCookies = new RequestCookies(headers);

        const sessionStore = new StatefulSessionStore({
          secret,
          store
        });

        const sessionFromDb = await sessionStore.get(requestCookies);
        expect(store.get).toHaveBeenCalledOnce();
        expect(store.get).toHaveBeenCalledWith(sessionId);
        expect(sessionFromDb).toEqual({
          user: { sub: "user_123", sid: "auth0-sid" },
          tokenSet: {},
          internal: {
            sid: "auth0-sid",
            createdAt: legacySession.header.iat
          }
        });
      });

      it("should convert legacy sessions with custom cookie names", async () => {
        const cookieName = "customSession";
        const sessionId = "ses_123";
        const secret = await generateSecret(32);
        const legacySession: LegacySessionPayload = {
          header: {
            iat: Math.floor(Date.now() / 1000),
            uat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000)
          },
          data: {
            user: {
              sub: "user_123",
              sid: "auth0-sid"
            },
            accessToken: "at_123",
            accessTokenScope: "openid profile email",
            refreshToken: "rt_123",
            accessTokenExpiresAt: 123456
          }
        };
        const store = {
          get: vi.fn().mockResolvedValue(legacySession),
          set: vi.fn(),
          delete: vi.fn()
        };
        const signedCookieValue = await sign(cookieName, sessionId, secret);

        const headers = new Headers();
        headers.append("cookie", `${cookieName}=${signedCookieValue}`);
        const requestCookies = new RequestCookies(headers);

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          cookieOptions: {
            name: cookieName
          }
        });

        const sessionFromDb = await sessionStore.get(requestCookies);
        expect(store.get).toHaveBeenCalledOnce();
        expect(store.get).toHaveBeenCalledWith(sessionId);
        expect(sessionFromDb).toEqual({
          user: { sub: "user_123", sid: "auth0-sid" },
          tokenSet: {
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456,
            scope: "openid profile email"
          },
          internal: {
            sid: "auth0-sid",
            createdAt: legacySession.header.iat
          }
        });
      });
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
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn()
        };

        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");
        const { payload: cookieValue } = await decrypt(cookie!.value, secret) as jose.JWTDecryptResult;

        expect(cookie).toBeDefined();
        expect(cookieValue).toHaveProperty("id");
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("lax");
        expect(cookie?.maxAge).toEqual(1800);
        expect(cookie?.secure).toEqual(false);

        expect(store.set).toHaveBeenCalledOnce();
        expect(store.set).toHaveBeenCalledWith(cookieValue.id, session);
      });

      it("should not exceed the absolute timeout duration", async () => {
        const currentTime = Date.now();
        const createdAt = Math.floor(currentTime / 1000);
        const secret = await generateSecret(32);
        const session: SessionData = {
          createdAt,
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
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn()
        };

        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800
        });

        // advance time by 2 hours - session should expire after 1 hour
        vi.setSystemTime(currentTime + 2 * 3600 * 1000);

        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");
        const { payload: cookieValue } = await decrypt(cookie!.value, secret) as jose.JWTDecryptResult;

        expect(cookie).toBeDefined();
        expect(cookieValue).toHaveProperty("id");
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("lax");
        expect(cookie?.maxAge).toEqual(0); // cookie should expire immedcreatedAtely
        expect(cookie?.secure).toEqual(false);

        expect(store.set).toHaveBeenCalledOnce();
        expect(store.set).toHaveBeenCalledWith(cookieValue.id, session);
      });
    });

    describe("with rolling sessions disabled", async () => {
      it("should set the cookie with a maxAge of the absolute session duration and call store.set", async () => {
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
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn()
        };

        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: false,
          absoluteDuration: 3600
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");
        const { payload: cookieValue } = await decrypt(cookie!.value, secret) as jose.JWTDecryptResult;

        expect(cookie).toBeDefined();
        expect(cookieValue).toHaveProperty("id");
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("lax");
        expect(cookie?.maxAge).toEqual(3600);
        expect(cookie?.secure).toEqual(false);

        expect(store.set).toHaveBeenCalledOnce();
        expect(store.set).toHaveBeenCalledWith(cookieValue.id, session);
      });
    });

    describe("session fixation", async () => {
      it("should generate a new session ID if the session is new", async () => {
        const sessionId = "ses_123";
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
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn()
        };
        const maxAge = 60 * 60; // 1 hour in seconds
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const encryptedCookieValue = await encrypt(
          {
            id: sessionId
          },
          secret,
          expiration,
        );
        const headers = new Headers();
        headers.append("cookie", `__session=${encryptedCookieValue}`);
        const requestCookies = new RequestCookies(headers);
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: false,
          absoluteDuration: 3600
        });
        await sessionStore.set(requestCookies, responseCookies, session, true);

        const cookie = responseCookies.get("__session");
        const { payload: cookieValue } = await decrypt(cookie!.value, secret) as jose.JWTDecryptResult;

        expect(cookie).toBeDefined();
        expect(store.delete).toHaveBeenCalledWith(sessionId); // the old session should be deleted
        expect(store.set).toHaveBeenCalledOnce();
        expect(store.set).toHaveBeenCalledWith(cookieValue.id, session); // a new session ID should be generated
      });
    });

    describe("with cookieOptions", async () => {
      it("should apply the secure attribute to the cookie", async () => {
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
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn()
        };

        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,

          cookieOptions: {
            secure: true
          }
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");
        const { payload: cookieValue } = await decrypt(cookie!.value, secret) as jose.JWTDecryptResult;

        expect(cookie).toBeDefined();
        expect(cookieValue).toHaveProperty("id");
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("lax");
        expect(cookie?.maxAge).toEqual(1800);
        expect(cookie?.secure).toEqual(true);
      });

      it("should apply the sameSite attribute to the cookie", async () => {
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
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn()
        };

        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,

          cookieOptions: {
            sameSite: "strict"
          }
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");
        const { payload: cookieValue } = await decrypt(cookie!.value, secret) as jose.JWTDecryptResult;

        expect(cookie).toBeDefined();
        expect(cookieValue).toHaveProperty("id");
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("strict");
        expect(cookie?.maxAge).toEqual(1800);
        expect(cookie?.secure).toEqual(false);
      });

      it("should apply the path to the cookie", async () => {
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
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn()
        };

        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,

          cookieOptions: {
            path: "/custom-path"
          }
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("__session");

        expect(cookie).toBeDefined();
        expect(cookie?.path).toEqual("/custom-path");
      });

      it("should apply the cookie name", async () => {
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
        const store = {
          get: vi.fn().mockResolvedValue(session),
          set: vi.fn(),
          delete: vi.fn()
        };

        const requestCookies = new RequestCookies(new Headers());
        const responseCookies = new ResponseCookies(new Headers());

        const sessionStore = new StatefulSessionStore({
          secret,
          store,
          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800,

          cookieOptions: {
            name: "my-session"
          }
        });
        await sessionStore.set(requestCookies, responseCookies, session);

        const cookie = responseCookies.get("my-session");
        const { payload: cookieValue } = await decrypt(cookie!.value, secret) as jose.JWTDecryptResult;

        expect(cookie).toBeDefined();
        expect(cookieValue).toHaveProperty("id");
        expect(cookie?.path).toEqual("/");
        expect(cookie?.httpOnly).toEqual(true);
        expect(cookie?.sameSite).toEqual("lax");
        expect(cookie?.maxAge).toEqual(1800);
        expect(cookie?.secure).toEqual(false);
      });
    });

    it("should remove the legacy cookie if it exists", async () => {
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
      const store = {
        get: vi.fn(),
        set: vi.fn(),
        delete: vi.fn()
      };

      const requestCookies = new RequestCookies(new Headers());
      const responseCookies = new ResponseCookies(new Headers());

      const sessionStore = new StatefulSessionStore({
        secret,
        store
      });

      vi.spyOn(requestCookies, "has").mockReturnValue(true);
      vi.spyOn(responseCookies, "delete");

      await sessionStore.set(requestCookies, responseCookies, session);

      expect(responseCookies.delete).toHaveBeenCalledWith(LEGACY_COOKIE_NAME);
    });
  });

  describe("delete", async () => {
    it("should remove the cookie and call store.delete with the session ID", async () => {
      const sessionId = "ses_123";
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
      const store = {
        get: vi.fn().mockResolvedValue(session),
        set: vi.fn(),
        delete: vi.fn()
      };
      const maxAge = 60 * 60; // 1 hour in seconds
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encryptedCookieValue = await encrypt(
        {
          id: sessionId
        },
        secret,
        expiration,
      );
      const headers = new Headers();
      headers.append("cookie", `__session=${encryptedCookieValue}`);
      const requestCookies = new RequestCookies(headers);
      const responseCookies = new ResponseCookies(new Headers());

      const sessionStore = new StatefulSessionStore({
        secret,
        store
      });
      await sessionStore.set(requestCookies, responseCookies, session);
      expect(responseCookies.get("__session")).toBeDefined();

      await sessionStore.delete(requestCookies, responseCookies);
      const cookie = responseCookies.get("__session");
      expect(cookie?.value).toEqual("");
      expect(cookie?.expires).toEqual(new Date("1970-01-01T00:00:00.000Z"));
      expect(store.delete).toHaveBeenCalledOnce();
      expect(store.delete).toHaveBeenCalledWith(sessionId);
    });

    it("should not throw an error if the cookie does not exist", async () => {
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
      const store = {
        get: vi.fn().mockResolvedValue(session),
        set: vi.fn(),
        delete: vi.fn()
      };
      const requestCookies = new RequestCookies(new Headers());
      const responseCookies = new ResponseCookies(new Headers());

      const sessionStore = new StatefulSessionStore({
        secret,
        store
      });

      await sessionStore.delete(requestCookies, responseCookies);
      const cookie = responseCookies.get("__session");
      expect(cookie?.value).toEqual("");
      expect(cookie?.expires).toEqual(new Date("1970-01-01T00:00:00.000Z"));
      expect(store.delete).not.toHaveBeenCalled();
    });
  });
});
