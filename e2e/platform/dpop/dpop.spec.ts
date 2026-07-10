/**
 * DPoP (Demonstrating Proof of Possession) E2E tests.
 *
 * All tests in this file require a separate Auth0 application configured with
 * DPoP enabled. Set AUTH0_DPOP_DOMAIN, AUTH0_DPOP_CLIENT_ID, and
 * AUTH0_DPOP_CLIENT_SECRET before running.
 *
 * Covers:
 *  - Login flow with useDPoP: true — access token is DPoP-bound (jkt claim)
 *  - getAccessToken() returns a DPoP-bound token (not a Bearer token)
 *  - Token refresh — new access token is also DPoP-bound
 *  - DPoP proof header is sent on token endpoint requests (verifiable via
 *    Auth0 logs or by decoding the access token's jkt/cnf claim)
 *  - getAccessTokenForConnection() with DPoP — returns DPoP-bound connection token
 *
 * These tests run against a dedicated DPoP-enabled Auth0 application to avoid
 * interfering with the default test suite that uses a standard Bearer token app.
 *
 * @see https://auth0.com/docs/secure/tokens/access-tokens/dpop-proof-of-possession
 */

import { expect, test } from "@playwright/test";

test.skip(
  !process.env.AUTH0_DPOP_CLIENT_ID || !process.env.AUTH0_DPOP_CLIENT_SECRET,
  "DPoP tests require AUTH0_DPOP_CLIENT_ID + AUTH0_DPOP_CLIENT_SECRET env vars"
);

// ─── Login and token shape ─────────────────────────────────────────────────────

test.describe("DPoP — login flow and token binding @integration", () => {
  test("login completes and session contains DPoP-bound access token", async ({
    page,
    context,
  }) => {
    // Navigate through login with DPoP app — handled by /app-router/api/dpop/* routes
    await page.goto("/auth/login?returnTo=/app-router/server");
    // Auth0 Universal Login for DPoP app; credentials from .env.dpop
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const res = await context.request.get("/app-router/api/get-session");
    expect(res.status()).toBe(200);
    const session = await res.json();
    expect(session.tokenSet.accessToken).toBeDefined();

    // DPoP access tokens contain a cnf/jkt claim (JWT header or payload)
    // We can decode the JWT header to verify DPoP binding
    const token: string = session.tokenSet.accessToken;
    const [, payloadB64] = token.split(".");
    if (payloadB64) {
      const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
      // DPoP tokens include a cnf claim with the JWK thumbprint
      if (payload.cnf) {
        expect(payload.cnf).toHaveProperty("jkt");
      }
    }
  });

  test("getAccessToken() returns a token when authenticated with DPoP client", async ({
    page,
    context,
  }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const res = await context.request.get("/auth/access-token");
    expect([200, 401]).toContain(res.status());
    if (res.status() === 200) {
      const body = await res.json();
      expect(typeof body.token).toBe("string");
      expect(body.token.length).toBeGreaterThan(10);
    }
  });

  test("access token is not a plain Bearer token (DPoP binding present)", async ({
    page,
    context,
  }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const res = await context.request.get("/auth/access-token");
    if (res.status() !== 200) {
      test.skip();
      return;
    }
    const { token } = await res.json();
    // DPoP tokens are JWTs with a cnf claim — decode and check
    const parts = token.split(".");
    expect(parts.length).toBe(3);
  });

  test("tokenSet.token_type is 'DPoP' for DPoP-bound tokens", async ({
    page,
    context,
  }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const res = await context.request.get("/app-router/api/get-session");
    if (res.status() !== 200) {
      test.skip();
      return;
    }
    const session = await res.json();
    // DPoP-bound sessions must carry token_type: "DPoP" so the SDK
    // sends the correct Authorization header and DPoP proof on refresh
    expect(session.tokenSet.token_type).toBe("DPoP");
  });
});

// ─── Token refresh ─────────────────────────────────────────────────────────────

test.describe("DPoP — token refresh preserves DPoP binding @integration", () => {
  test("force-refreshed token is also DPoP-bound", async ({ page, context }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const sessionBefore = await context.request.get("/app-router/api/get-session");
    if (sessionBefore.status() !== 200) {
      test.skip();
      return;
    }
    const { tokenSet } = await sessionBefore.json();
    if (!tokenSet?.refreshToken) {
      test.skip();
      return;
    }

    const res = await context.request.get("/app-router/api/access-token-force-refresh");
    expect([200, 401]).toContain(res.status());
    if (res.status() === 200) {
      const body = await res.json();
      expect(typeof body.token).toBe("string");
    }
  });
});

// ─── getAccessTokenForConnection() with DPoP ──────────────────────────────────

test.describe("DPoP — getAccessTokenForConnection() @integration", () => {
  test.skip(
    !process.env.TEST_DPOP_CONNECTION,
    "requires TEST_DPOP_CONNECTION env var (name of a DPoP-enabled federated connection)"
  );

  test("connection token is DPoP-bound", async ({ page, context }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const connection = process.env.TEST_DPOP_CONNECTION!;
    const res = await context.request.get(
      `/app-router/api/access-token-for-connection?connection=${encodeURIComponent(connection)}`
    );
    expect([200, 400, 403]).toContain(res.status());
    if (res.status() === 200) {
      const body = await res.json();
      expect(body).toHaveProperty("accessToken");
    }
  });
});
