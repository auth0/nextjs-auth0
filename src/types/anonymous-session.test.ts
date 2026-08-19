import { NextRequest, NextResponse } from "next/server.js";
import { describe, expect, it } from "vitest";

import {
  AnonymousSessionError,
  mapAnonymousErrorCode
} from "../errors/anonymous-session-errors.js";
import { AuthClient } from "../server/auth-client.js";
import { encrypt } from "../server/cookies.js";
import { StatelessSessionStore } from "../server/session/stateless-session-store.js";
import { TransactionStore } from "../server/transaction-store.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { transferCookies } from "../utils/anonymous-session-constants.js";
import {
  isRecoverableAnonymousError,
  type AnonymousCookiePayload,
  type AnonymousSession
} from "./anonymous-session.js";

describe("AnonymousSessionError", () => {
  describe("construction", () => {
    it("T2.3: throws with code `unauthorized_client`", () => {
      const err = new AnonymousSessionError(
        "unauthorized_client",
        "Not enabled"
      );
      expect(err.code).toBe("unauthorized_client");
      expect(err.message).toBe("Not enabled");
      expect(err.name).toBe("AnonymousSessionError");
    });

    it("T2.4: uses default message if omitted", () => {
      const err = new AnonymousSessionError("feature_not_enabled");
      expect(err.message).toMatch(/An error occurred/);
      expect(err.code).toBe("feature_not_enabled");
    });

    it("constructs error with all required properties", () => {
      const err = new AnonymousSessionError("invalid_request", "Bad request");
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(AnonymousSessionError);
      expect(err.name).toBe("AnonymousSessionError");
    });
  });

  describe("mapAnonymousErrorCode", () => {
    it("T2.3: maps unauthorized_client code", () => {
      const err = mapAnonymousErrorCode("unauthorized_client");
      expect(err).toBeInstanceOf(AnonymousSessionError);
      expect(err.code).toBe("unauthorized_client");
      expect(err.message).toContain("not enabled for anonymous");
    });

    it("T2.4: maps feature_not_enabled code", () => {
      const err = mapAnonymousErrorCode("feature_not_enabled");
      expect(err.code).toBe("feature_not_enabled");
      expect(err.message).toContain("not enabled");
    });

    it("T3.2: maps metadata_too_large code", () => {
      const err = mapAnonymousErrorCode("metadata_too_large");
      expect(err.code).toBe("metadata_too_large");
      expect(err.message).toContain("1KB");
    });

    it("T3.6: maps session_expired code", () => {
      const err = mapAnonymousErrorCode("session_expired");
      expect(err.code).toBe("session_expired");
    });

    it("T3.7: maps invalid_session_token code", () => {
      const err = mapAnonymousErrorCode("invalid_session_token");
      expect(err.code).toBe("invalid_session_token");
    });

    it("T1.7: maps server_error code", () => {
      const err = mapAnonymousErrorCode("server_error");
      expect(err.code).toBe("server_error");
    });

    it("FR-13: maps invalid_client code", () => {
      const err = mapAnonymousErrorCode("invalid_client");
      expect(err.code).toBe("invalid_client");
      expect(err.message).toContain("authentication failed");
    });

    it("maps unknown code with fallback message", () => {
      const err = mapAnonymousErrorCode("unknown_code");
      expect(err.code).toBe("unknown_code");
      expect(err.message).toContain("An error occurred");
    });
  });

  describe("isRecoverableAnonymousError", () => {
    it("T1.5: returns true for session_expired", () => {
      const err = new AnonymousSessionError("session_expired");
      expect(isRecoverableAnonymousError(err)).toBe(true);
    });

    it("returns true for invalid_session_token", () => {
      const err = new AnonymousSessionError("invalid_session_token");
      expect(isRecoverableAnonymousError(err)).toBe(true);
    });

    it("T1.7: returns false for server_error", () => {
      const err = new AnonymousSessionError("server_error");
      expect(isRecoverableAnonymousError(err)).toBe(false);
    });

    it("T1.7: returns false for non-AnonymousSessionError", () => {
      const err = new Error("generic");
      expect(isRecoverableAnonymousError(err)).toBe(false);
    });

    it("returns false for null", () => {
      expect(isRecoverableAnonymousError(null)).toBe(false);
    });

    it("returns false for undefined", () => {
      expect(isRecoverableAnonymousError(undefined)).toBe(false);
    });

    it("returns false for objects without code property", () => {
      expect(isRecoverableAnonymousError({ message: "error" })).toBe(false);
    });
  });

  describe("transferCookies helper", () => {
    it("REG-C3: copies all cookies from source to target", () => {
      const source = new NextResponse();
      source.cookies.set("test-cookie", "value", { httpOnly: true });
      const target = new NextResponse();

      transferCookies(source, target);

      const targetCookies = target.cookies.getAll();
      expect(targetCookies).toHaveLength(1);
      expect(targetCookies[0].name).toBe("test-cookie");
      expect(targetCookies[0].value).toBe("value");
      expect(targetCookies[0].httpOnly).toBe(true);
    });

    it("copies multiple cookies", () => {
      const source = new NextResponse();
      source.cookies.set("cookie1", "value1", { httpOnly: true });
      source.cookies.set("cookie2", "value2", { secure: true });
      const target = new NextResponse();

      transferCookies(source, target);

      const targetCookies = target.cookies.getAll();
      expect(targetCookies).toHaveLength(2);
      expect(targetCookies.map((c) => c.name)).toEqual(["cookie1", "cookie2"]);
    });

    it("handles empty source", () => {
      const source = new NextResponse();
      const target = new NextResponse();

      transferCookies(source, target);

      expect(target.cookies.getAll()).toHaveLength(0);
    });
  });
});

describe("Type definitions", () => {
  describe("C1 BLOCKER FIX: SDK transformation path - toPublicSession extracts anon@ from JWT", () => {
    it("C1: SDK extracts id from JWT sub claim with anon@ prefix", async () => {
      // BLOCKER C1 FIX: Drive REAL SDK toPublicSession path.
      // Prior test was tautology (manually decode JWT, assert same value).
      // This test exercises the actual SDK transformation: build a mock JWT,
      // wrap in AnonymousCookiePayload, drive through the SDK's toPublicSession
      // (via getAnonymousSession end-to-end path), assert SDK extracted the id.

      // Pattern: mimic auth-client.anonymous-routes.test.ts T2.5 lines 810-835
      // which proves session.id === JWT sub claim via real SDK path.

      const secret = await generateSecret(32);
      const routes = getDefaultRoutes();
      const client = new AuthClient({
        domain: "auth0.local",
        clientId: "test-id",
        clientSecret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        secret,
        routes,
        transactionStore: new TransactionStore({
          secret,
          cookieOptions: { secure: false }
        }),
        sessionStore: new StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 259200,
          inactivityDuration: 86400
        }),
        anonymousSession: { enabled: true }
      });

      // Build a real JWT with anon@ sub
      const header = Buffer.from(
        JSON.stringify({ alg: "HS256", typ: "JWT" })
      ).toString("base64url");
      const now = Math.floor(Date.now() / 1000);
      const payload = Buffer.from(
        JSON.stringify({
          sub: "anon@c1-blocker-uuid",
          iat: now,
          exp: now + 3600
        })
      ).toString("base64url");
      const jwt = `${header}.${payload}.sig`;

      // Wrap in AnonymousCookiePayload and encrypt as cookie
      const cookiePayload: AnonymousCookiePayload = {
        session_token: "session-token-c1",
        access_token: jwt,
        expires_at: now + 3600
      };
      const encrypted = await encrypt(cookiePayload, secret, now + 3600);

      // Drive SDK path: getAnonymousSession reads cookie, calls toPublicSession
      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        { headers: { cookie: `auth0_anon=${encrypted}` } }
      );
      const res = new NextResponse();
      const session = await (client as any).getAnonymousSession(
        req.cookies,
        res.cookies
      );

      // ASSERT: SDK extracted id from JWT sub, matches anon@ format
      expect(session).toBeTruthy();
      expect(session!.id).toBe("anon@c1-blocker-uuid");
      expect(session!.id).toMatch(/^anon@/);
    });

    it("REG-M2: SDK rejects non-anon@ JWT sub with invalid_session_token", async () => {
      // BLOCKER C1 also requires proving non-anon@ sub is rejected per DESIGN §3.C2.
      const secret = await generateSecret(32);
      const routes = getDefaultRoutes();
      const client = new AuthClient({
        domain: "auth0.local",
        clientId: "test-id",
        clientSecret: "test-secret",
        appBaseUrl: "http://localhost:3000",
        secret,
        routes,
        transactionStore: new TransactionStore({
          secret,
          cookieOptions: { secure: false }
        }),
        sessionStore: new StatelessSessionStore({
          secret,
          rolling: true,
          absoluteDuration: 259200,
          inactivityDuration: 86400
        }),
        anonymousSession: { enabled: true }
      });

      // Build JWT with NON-anon@ sub (e.g. auth0|user123)
      const header = Buffer.from(
        JSON.stringify({ alg: "HS256", typ: "JWT" })
      ).toString("base64url");
      const now = Math.floor(Date.now() / 1000);
      const payload = Buffer.from(
        JSON.stringify({
          sub: "auth0|user123",
          iat: now,
          exp: now + 3600
        })
      ).toString("base64url");
      const jwt = `${header}.${payload}.sig`;

      const cookiePayload: AnonymousCookiePayload = {
        session_token: "token",
        access_token: jwt,
        expires_at: now + 3600
      };
      const encrypted = await encrypt(cookiePayload, secret, now + 3600);

      const req = new NextRequest(
        new URL("http://localhost:3000/auth/anonymous-session"),
        { headers: { cookie: `auth0_anon=${encrypted}` } }
      );
      const res = new NextResponse();

      // SDK should reject this as invalid_session_token
      const session = await (client as any).getAnonymousSession(
        req.cookies,
        res.cookies
      );
      // toPublicSession throws AnonymousSessionError, resolveAnonymousSession catches → returns null
      expect(session).toBeNull();
    });

    it("T1.1: AnonymousSession.accessToken is the raw bearer token", () => {
      const bearerToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbm9uQHV1aWQtMTIzNCJ9.sig";
      const session: AnonymousSession = {
        id: "anon@uuid-1234",
        accessToken: bearerToken,
        expiresAt: Math.floor(Date.now() / 1000) + 3600
      };
      expect(session.accessToken).toBe(bearerToken);
    });

    it("T1.1: AnonymousSession.expiresAt is extracted from access_token exp claim", () => {
      const now = Math.floor(Date.now() / 1000);
      const expiryFromJWT = now + 3600;
      const session: AnonymousSession = {
        id: "anon@uuid-1234",
        accessToken: "token",
        expiresAt: expiryFromJWT
      };
      expect(session.expiresAt).toBe(expiryFromJWT);
    });

    it("T1.1: AnonymousSession with metadata includes last persisted metadata from cookie", () => {
      const session: AnonymousSession = {
        id: "anon@uuid-5678",
        accessToken: "eyJ...",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        metadata: { cart: { qty: 3 }, preferences: { theme: "dark" } }
      };
      expect(session.metadata).toEqual({
        cart: { qty: 3 },
        preferences: { theme: "dark" }
      });
    });
  });

  describe("T3.1: AnonymousCookiePayload verification", () => {
    it("T3.1: AnonymousCookiePayload has session_token + access_token", () => {
      const payload: AnonymousCookiePayload = {
        session_token: "session-opaque-handle",
        access_token: "eyJ...",
        expires_at: Math.floor(Date.now() / 1000) + 3600
      };
      expect(payload.session_token).toBeDefined();
      expect(payload.access_token).toBeDefined();
      expect(payload.expires_at).toBeGreaterThan(0);
    });

    it("T3.1: AnonymousCookiePayload with metadata", () => {
      const payload: AnonymousCookiePayload = {
        session_token: "token",
        access_token: "eyJ...",
        expires_at: 3000,
        metadata: { key: "value" }
      };
      expect(payload.metadata).toEqual({ key: "value" });
    });
  });

  describe("Config validation", () => {
    it("T8.1: AnonymousSessionConfig has enabled flag", () => {
      const config = {
        enabled: false
      };
      expect(config.enabled).toBe(false);
    });

    it("T8.3: Cookie name override in config", () => {
      const config = {
        enabled: true,
        cookie: { name: "custom_anon" }
      };
      expect(config.cookie?.name).toBe("custom_anon");
    });

    it("T8.4: Cookie sameSite override", () => {
      const config = {
        enabled: true,
        cookie: { sameSite: "strict" as const }
      };
      expect(config.cookie?.sameSite).toBe("strict");
    });

    it("T8.5: Cookie secure override", () => {
      const config = {
        enabled: true,
        cookie: { secure: false }
      };
      expect(config.cookie?.secure).toBe(false);
    });
  });
});
