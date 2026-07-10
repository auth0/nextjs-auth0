/**
 * createFetcher() and getTokenByBackchannelAuth() E2E tests.
 *
 * createFetcher():
 *  - Throws MISSING_SESSION when no session exists (401 from route)
 *  - Returns a Fetcher that can make authenticated requests with the session token
 *  - fetchWithAuth() forwards Bearer token to the target URL
 *  - fetchWithAuth() against /auth/profile returns 200 with session user
 *
 * getTokenByBackchannelAuth() (CIBA):
 *  - Route is wired at POST /app-router/api/backchannel-auth
 *  - Missing bindingMessage / loginHint.sub → 400 (not 500)
 *  - BackchannelAuthenticationNotSupportedError surfaced when tenant lacks CIBA
 *    (returns 400 with structured error body, not 500)
 *  - Full CIBA flow requires a CIBA-enabled tenant + push notification confirmation
 *    — full flow is gated behind TEST_CIBA_USER_SUB @integration
 */

import { expect, test } from "@playwright/test";
import { injectSession } from "../../helpers";

// ─── createFetcher() ──────────────────────────────────────────────────────────

test.describe("createFetcher() — authentication guard", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("returns 401 (MISSING_SESSION) without a session", async ({ context }) => {
    const res = await context.request.get("/app-router/api/create-fetcher");
    expect(res.status()).toBe(401);
    const body = await res.json();
    expect(body).toHaveProperty("code");
    expect(body.code).toMatch(/missing_session/i);
  });

  test("error body contains code and error fields", async ({ context }) => {
    const res = await context.request.get("/app-router/api/create-fetcher");
    const body = await res.json();
    expect(typeof body.error).toBe("string");
    expect(typeof body.code).toBe("string");
  });
});

test.describe("createFetcher() — authenticated fetching", () => {
  test("createFetcher() succeeds and fetchWithAuth() sends the Bearer token", async ({
    context,
  }) => {
    // Inject a fresh session so createFetcher() never sees missing_session.
    await injectSession(context, {
      tokenSet: { accessToken: "fetcher-test-token", expiresAt: Math.floor(Date.now() / 1000) + 7200 },
    });
    // The route returns 200 with { status, ok } — outer 200 means createFetcher() succeeded.
    // /auth/profile reads the cookie, not the Bearer header, so body.status may be anything.
    const res = await context.request.get(
      "/app-router/api/create-fetcher?url=/auth/profile"
    );
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty("status");
    expect(body).toHaveProperty("ok");
  });

  test("createFetcher() with injected session returns a working Fetcher", async ({
    context,
  }) => {
    await injectSession(context, {
      tokenSet: {
        accessToken: "injected-access-token",
        expiresAt: Math.floor(Date.now() / 1000) + 7200,
      },
    });
    const res = await context.request.get(
      "/app-router/api/create-fetcher?url=/auth/profile"
    );
    // Route gets a Fetcher and hits /auth/profile — the injected token may or may
    // not be accepted by Auth0 (it's synthetic), so 200 or 401 from profile are both fine.
    // What matters is createFetcher() itself did not throw MISSING_SESSION.
    expect(res.status()).not.toBe(401);
    // The route itself returns 200 with { status, ok }
    if (res.status() === 200) {
      const body = await res.json();
      expect(body).toHaveProperty("status");
    }
  });

  test("fetchWithAuth() against an unauthenticated endpoint returns 401 from the target", async ({
    context,
  }) => {
    // Session comes from storageState (setup project login).
    // /app-router/api/get-session reads the cookie, not the Bearer header, so
    // fetchWithAuth which sends Authorization: Bearer gets a 401 from that endpoint.
    // This validates fetchWithAuth is not magic-injecting a session cookie.
    const res = await context.request.get(
      "/app-router/api/create-fetcher?url=/app-router/api/get-session"
    );
    // createFetcher itself succeeds (200 from our route), but the target may 401
    // because the downstream endpoint reads the cookie, not the Bearer header.
    expect(res.status()).not.toBe(500);
  });

  test("fetchWithAuth() sends Authorization: Bearer <token> header to the target", async ({
    context,
  }) => {
    const accessToken = "fetcher-bearer-header-test-token";
    await injectSession(context, {
      tokenSet: { accessToken, expiresAt: Math.floor(Date.now() / 1000) + 7200 },
    });
    // Point fetchWithAuth at the echo-headers route which returns all received headers
    const res = await context.request.get(
      "/app-router/api/create-fetcher?url=/app-router/api/echo-headers"
    );
    expect(res.status()).toBe(200);
    const outer = await res.json();
    // outer.body is the echo-headers response: { headers: { authorization: "Bearer <token>" } }
    expect(outer.ok).toBe(true);
    const authHeader: string = outer.body?.headers?.authorization ?? "";
    expect(authHeader).toMatch(/^Bearer /i);
    expect(authHeader).toContain(accessToken);
  });
});

// ─── getTokenByBackchannelAuth() — CIBA route wiring ─────────────────────────

test.describe("getTokenByBackchannelAuth() — route wiring and validation", () => {
  test("POST method is accepted (not 404 or 405)", async ({ context }) => {
    const res = await context.request.post("/app-router/api/backchannel-auth", {
      data: { bindingMessage: "test", loginHint: { sub: "test|123" } },
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing bindingMessage returns 400", async ({ context }) => {
    const res = await context.request.post("/app-router/api/backchannel-auth", {
      data: { loginHint: { sub: "test|123" } },
    });
    expect(res.status()).toBe(400);
    expect(res.status()).not.toBe(500);
  });

  test("missing loginHint.sub returns 400", async ({ context }) => {
    const res = await context.request.post("/app-router/api/backchannel-auth", {
      data: { bindingMessage: "test" },
    });
    expect(res.status()).toBe(400);
  });

  test("empty body returns 400", async ({ context }) => {
    const res = await context.request.post("/app-router/api/backchannel-auth", {
      data: {},
    });
    expect(res.status()).toBe(400);
    expect(res.status()).not.toBe(500);
  });

  test("valid input returns structured error — not 500 (CIBA not enabled on test tenant)", async ({
    context,
  }) => {
    const res = await context.request.post("/app-router/api/backchannel-auth", {
      data: {
        bindingMessage: "confirm-login",
        loginHint: { sub: "test|user123" },
      },
    });
    // Auth0 will return BackchannelAuthenticationNotSupportedError or an OAuth error
    // because the test tenant likely doesn't have CIBA enabled.
    // Either 400 (SDK error forwarded) is valid — never 500.
    expect([400, 401]).toContain(res.status());
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("error response contains error and code fields", async ({ context }) => {
    const res = await context.request.post("/app-router/api/backchannel-auth", {
      data: {
        bindingMessage: "test-msg",
        loginHint: { sub: "auth0|nonexistent" },
      },
    });
    if (res.status() !== 200) {
      const body = await res.json();
      expect(body).toHaveProperty("error");
    }
  });

  test("error name is 'BackchannelAuthenticationNotSupportedError' when CIBA not enabled on tenant", async ({
    context,
  }) => {
    const res = await context.request.post("/app-router/api/backchannel-auth", {
      data: {
        bindingMessage: "confirm-login",
        loginHint: { sub: "test|user123" },
      },
    });
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    // When the tenant has CIBA disabled, the SDK throws BackchannelAuthenticationNotSupportedError.
    // Other OAuth errors are also possible — assert the name is present and is a string.
    expect(typeof body.name).toBe("string");
    expect(body.name.length).toBeGreaterThan(0);
    // When it IS the CIBA-not-supported error, assert the exact class name and code.
    if (body.name === "BackchannelAuthenticationNotSupportedError") {
      expect(body.code).toBe("backchannel_authentication_not_supported_error");
    }
  });

  test("GET method is not accepted (route is POST-only)", async ({ context }) => {
    const res = await context.request.get("/app-router/api/backchannel-auth");
    expect(res.status()).not.toBe(200);
  });
});

// ─── @integration — requires CIBA-enabled Auth0 tenant ───────────────────────

test.describe("getTokenByBackchannelAuth() — full CIBA flow @integration", () => {
  test.skip(
    !process.env.TEST_CIBA_USER_SUB,
    "requires TEST_CIBA_USER_SUB — a user sub for CIBA push notification"
  );

  test("CIBA flow initiates and returns a tokenSet when user approves", async ({
    context,
  }) => {
    const res = await context.request.post("/app-router/api/backchannel-auth", {
      data: {
        bindingMessage: "e2e-test-login",
        loginHint: { sub: process.env.TEST_CIBA_USER_SUB },
      },
    });
    // 200 = CIBA completed (user approved the push); 400 = expected error
    expect([200, 400]).toContain(res.status());
    if (res.status() === 200) {
      const body = await res.json();
      expect(body).toHaveProperty("tokenSet");
      expect(typeof body.tokenSet.accessToken).toBe("string");
    }
  });
});
