import * as jose from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { generateSecret } from "../../test/utils.js";
import { CookieOptions, SessionData } from "../../types/index.js";
import {
  decrypt,
  encrypt,
  RequestCookies,
  ResponseCookies
} from "../cookies.js";
import * as cookies from "../cookies.js";
import { LEGACY_COOKIE_NAME, LegacySession } from "./normalize-session.js";
import { StatelessSessionStore } from "./stateless-session-store.js";

describe("Stateless Session Store", async () => {
  const baseCookieOptions: CookieOptions = {
    path: "/",
    httpOnly: true,
    sameSite: "lax",
    secure: false
  };

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
        `__session=${encryptedCookieValue};__FC.0=${encryptedGoogleConnectionCookieValue}`
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
        `__session=${encryptedCookieValue};__FC.0=${encryptedGoogleConnectionCookieValue};__FC.1=${encryptedGithubConnectionCookieValue}`
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
        vi.spyOn(requestCookies, "has").mockReturnValue(true);

        await sessionStore.set(requestCookies, responseCookies, session);

        expect(responseCookies.set).toHaveBeenCalledWith(
          LEGACY_COOKIE_NAME,
          "",
          {
            maxAge: 0
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
        vi.spyOn(requestCookies, "getAll").mockReturnValue([
          { name: `${LEGACY_COOKIE_NAME}.0`, value: "" },
          { name: `${LEGACY_COOKIE_NAME}.1`, value: "" }
        ]);

        await sessionStore.set(requestCookies, responseCookies, session);

        expect(responseCookies.set).toHaveBeenCalledTimes(4);
        expect(responseCookies.set).toHaveBeenNthCalledWith(
          1,
          "__session",
          expect.any(String),
          expect.not.objectContaining({ maxAge: 0 })
        );
        expect(responseCookies.set).toHaveBeenNthCalledWith(
          2,
          LEGACY_COOKIE_NAME,
          "",
          { maxAge: 0 }
        );
        expect(responseCookies.set).toHaveBeenNthCalledWith(
          3,
          `${LEGACY_COOKIE_NAME}.0`,
          "",
          { maxAge: 0 }
        );
        expect(responseCookies.set).toHaveBeenNthCalledWith(
          4,
          `${LEGACY_COOKIE_NAME}.1`,
          "",
          { maxAge: 0 }
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

      // set should be called once for setting the new session cookie and once for deleting the legacy cookie
      expect(setSpy).toHaveBeenCalledTimes(2);
      expect(setSpy).toHaveBeenNthCalledWith(
        1,
        "__session",
        expect.any(String),
        expect.not.objectContaining({ maxAge: 0 })
      );
      expect(setSpy).toHaveBeenNthCalledWith(
        2,
        legacyCookiesInSetup[0].name,
        "",
        {
          maxAge: 0
        }
      );
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
  });
});
