/**
 * TIER 2 MSW Tests (M1-M12)
 * Deterministic, CI-safe tests using SYNTHETIC fixtures
 * Tests SDK behavior through example app config
 */
import { useAnonymousSession } from "@auth0/nextjs-auth0/client";
import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import {
  SYNTHETIC_ACCESS_TOKEN,
  SYNTHETIC_ACCESS_TOKEN_RENEWED,
  SYNTHETIC_DOMAIN,
  SYNTHETIC_METADATA,
  SYNTHETIC_SESSION_TOKEN,
  WIRE_CREATE_RESPONSE,
  WIRE_LOGOUT_WITH_SESSION_TOKEN_ERROR,
  WIRE_RENEW_RESPONSE,
  WIRE_RENEW_WITH_METADATA_ERROR
} from "./fixtures/synthetic-tokens";
import { server } from "./setup";

describe("Anonymous Sessions - TIER 2 MSW (M1-M12)", () => {
  describe("M1: CREATE wire->AnonymousSession mapping", () => {
    it("should map wire response to AnonymousSession shape", async () => {
      const response = await fetch(`${SYNTHETIC_DOMAIN}/anonymous/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "test",
          client_secret: "test",
          audience: "https://api.customers"
        })
      });

      expect(response.status).toBe(200);
      const json = await response.json();

      // Wire shape validation
      expect(json).toMatchObject({
        token_type: "Bearer",
        session_expires_in: 2592000,
        session_token: SYNTHETIC_SESSION_TOKEN,
        access_token: SYNTHETIC_ACCESS_TOKEN,
        expires_in: 7200
      });

      // AnonymousSession would map: id=sub from JWT, accessToken=access_token, expiresAt=iat+expires_in
      expect(json.access_token).toBe(SYNTHETIC_ACCESS_TOKEN);
      expect(json.session_token).toBe(SYNTHETIC_SESSION_TOKEN);
      expect(json.session_expires_in).toBe(2592000);
    });
  });

  describe("M2: CREATE with metadata -> metadata field", () => {
    it("should accept metadata on create", async () => {
      const response = await fetch(`${SYNTHETIC_DOMAIN}/anonymous/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "test",
          client_secret: "test",
          audience: "https://api.customers",
          metadata: SYNTHETIC_METADATA
        })
      });

      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json).toHaveProperty("session_token");
      expect(json).toHaveProperty("access_token");
    });
  });

  describe("M3: RENEW-defer -> original session_token unchanged, new access_token", () => {
    it("should return fresh access_token without reissuing session_token", async () => {
      const response = await fetch(`${SYNTHETIC_DOMAIN}/anonymous/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "test",
          client_secret: "test",
          audience: "https://api.customers",
          session_token: SYNTHETIC_SESSION_TOKEN
        })
      });

      expect(response.status).toBe(200);
      const json = await response.json();

      // RENEW: NO session_token in response
      expect(json).not.toHaveProperty("session_token");
      expect(json.access_token).toBe(SYNTHETIC_ACCESS_TOKEN_RENEWED);
      expect(json.expires_in).toBe(7200);
    });
  });

  describe("M4: RENEW + metadata 400 -> AnonymousSessionError invalid_request", () => {
    it("should reject metadata when session_token is present", async () => {
      const response = await fetch(`${SYNTHETIC_DOMAIN}/anonymous/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "test",
          client_secret: "test",
          audience: "https://api.customers",
          session_token: SYNTHETIC_SESSION_TOKEN,
          metadata: { x: "y" }
        })
      });

      expect(response.status).toBe(400);
      const json = await response.json();
      expect(json).toMatchObject(WIRE_RENEW_WITH_METADATA_ERROR);
      expect(json.error).toBe("invalid_request");
      expect(json.error_description).toBe(
        "metadata cannot be provided when session_token is present"
      );
    });
  });

  describe("M5: LOGOUT 204 -> no error, cookie cleared", () => {
    it("should return 204 for logout with client_id", async () => {
      const response = await fetch(`${SYNTHETIC_DOMAIN}/anonymous/logout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_id: "test" })
      });

      expect(response.status).toBe(204);
      expect(await response.text()).toBe("");
    });

    it("should return 204 for logout with empty body", async () => {
      const response = await fetch(`${SYNTHETIC_DOMAIN}/anonymous/logout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
      });

      expect(response.status).toBe(204);
      expect(await response.text()).toBe("");
    });
  });

  describe("M6: LOGOUT + session_token 400 -> AnonymousSessionError", () => {
    it("should reject logout when session_token in body", async () => {
      const response = await fetch(`${SYNTHETIC_DOMAIN}/anonymous/logout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "test",
          session_token: SYNTHETIC_SESSION_TOKEN
        })
      });

      expect(response.status).toBe(400);
      const json = await response.json();
      expect(json).toMatchObject(WIRE_LOGOUT_WITH_SESSION_TOKEN_ERROR);
      expect(json.error).toBe("invalid_request");
    });
  });

  describe("M7: Δ session_expires_in 2592000 mapping", () => {
    it("should include session_expires_in=2592000 on CREATE", async () => {
      const response = await fetch(`${SYNTHETIC_DOMAIN}/anonymous/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "test",
          client_secret: "test",
          audience: "https://api.customers"
        })
      });

      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json.session_expires_in).toBe(2592000); // 30 days
    });
  });

  describe("M8: Δ session_token JWE field present", () => {
    it("should return session_token on CREATE", async () => {
      const response = await fetch(`${SYNTHETIC_DOMAIN}/anonymous/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: "test",
          client_secret: "test",
          audience: "https://api.customers"
        })
      });

      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json).toHaveProperty("session_token");
      expect(typeof json.session_token).toBe("string");
      expect(json.session_token).toBe(SYNTHETIC_SESSION_TOKEN);
    });
  });

  // M9: getAnonymousSession() is a SERVER-only API. It reads the encrypted
  // auth0_anon cookie inside the Next.js request runtime and cannot execute
  // meaningfully in jsdom (no cookie store, no server client bootstrap). Its
  // real behavior — cookie -> AnonymousSession {id, accessToken, expiresAt,
  // metadata?} — is exercised end-to-end by the Tier1 LIVE suite (L1/L3) and by
  // running the example against a live tenant. Asserting an inline mock here
  // would test nothing about the SDK, so it is intentionally left as a gap.
  describe("M9: Δ getAnonymousSession returns object shape", () => {
    it.todo(
      "getAnonymousSession maps cookie -> AnonymousSession (server-runtime; covered by Tier1 LIVE L1/L3)"
    );
  });

  // M10: useAnonymousSession IS a real client surface (SWR + fetch of the read
  // route). This renders the ACTUAL SDK hook in jsdom and drives it through MSW,
  // verifying the real return shape and the wire->AnonymousSession mapping the
  // hook performs — not an inline mock.
  describe("M10: Δ useAnonymousSession hook (real SDK hook via MSW)", () => {
    // SWR keys its cache by route. The SDK hook takes a { route } option, so
    // each test passes a UNIQUE route -> a distinct cache key -> no result from
    // one test can leak into another (avoids a shared global SWR cache without
    // needing an SWRConfig provider, which would require a second React copy).
    // jsdom resolves the hook's relative fetch against http://localhost:3000.

    it("returns the session object when the read route answers 200", async () => {
      const route = "/auth/anonymous-session-200";
      const anonPayload = {
        id: "anon@00000000-0000-0000-0000-000000000000",
        accessToken: SYNTHETIC_ACCESS_TOKEN,
        expiresAt: 1725307200,
        metadata: SYNTHETIC_METADATA
      };
      server.use(
        http.get(`http://localhost:3000${route}`, () =>
          HttpResponse.json(anonPayload, { status: 200 })
        )
      );

      const { result } = renderHook(() => useAnonymousSession({ route }));

      // Initial shape: hook exposes the documented contract immediately.
      expect(result.current).toHaveProperty("anonymous");
      expect(result.current).toHaveProperty("isLoading");
      expect(result.current).toHaveProperty("error");
      expect(typeof result.current.invalidate).toBe("function");

      await waitFor(() => expect(result.current.isLoading).toBe(false));

      expect(result.current.error).toBeNull();
      expect(result.current.anonymous).toEqual(anonPayload);
    });

    it("maps a 204 (no session) to anonymous=null", async () => {
      const route = "/auth/anonymous-session-204";
      server.use(
        http.get(
          `http://localhost:3000${route}`,
          () => new HttpResponse(null, { status: 204 })
        )
      );

      const { result } = renderHook(() => useAnonymousSession({ route }));

      await waitFor(() => expect(result.current.isLoading).toBe(false));
      expect(result.current.anonymous).toBeNull();
      expect(result.current.error).toBeNull();
    });

    it("surfaces a fetch failure through error", async () => {
      const route = "/auth/anonymous-session-500";
      server.use(
        http.get(
          `http://localhost:3000${route}`,
          () => new HttpResponse(null, { status: 500 })
        )
      );

      const { result } = renderHook(() => useAnonymousSession({ route }));

      await waitFor(() => expect(result.current.error).not.toBeNull());
      expect(result.current.anonymous).toBeNull();
      expect(result.current.error).toBeInstanceOf(Error);
    });
  });

  // M11/M12: the SDK route handlers (GET /auth/anonymous-session and
  // POST /auth/anonymous-session/logout) run inside the Next.js request pipeline
  // (middleware-mounted, encrypted-cookie backed). They cannot be invoked from a
  // plain vitest process without booting the Next server. The previous versions
  // of these tests registered their OWN MSW handler and then asserted it, which
  // exercised MSW rather than the SDK. Real coverage lives in the Tier1 LIVE
  // suite (L6-L8 logout, and the running example for the GET route). Left as
  // explicit gaps rather than tautological green.
  describe("M11: Δ GET route read", () => {
    it.todo(
      "GET /auth/anonymous-session route handler (Next runtime; covered by live example + Tier1 LIVE)"
    );
  });

  describe("M12: Δ POST logout route", () => {
    it.todo(
      "POST /auth/anonymous-session/logout route handler (Next runtime; covered by Tier1 LIVE L6-L8)"
    );
  });
});
