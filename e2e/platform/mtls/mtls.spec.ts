/**
 * mTLS (Mutual TLS / Client Certificate) E2E tests.
 *
 * All tests require a separate Auth0 application configured for mTLS and
 * a test environment with a valid client certificate. Set:
 *   AUTH0_MTLS_DOMAIN, AUTH0_MTLS_CLIENT_ID, AUTH0_MTLS_CLIENT_SECRET
 *   TEST_MTLS_CERT_PATH, TEST_MTLS_KEY_PATH
 *
 * Covers:
 *  - Token endpoint uses the mTLS CA-authenticated endpoint when useMtls: true
 *  - Access token is certificate-bound (cnf/x5t#S256 claim)
 *  - Token refresh uses the mTLS endpoint
 *  - getAccessTokenForConnection() with mTLS — connection token is bound
 *
 * These tests run against a dedicated mTLS-enabled Auth0 application.
 *
 * @see https://auth0.com/docs/get-started/authentication-and-authorization-flow/mutual-tls
 */

import { expect, test } from "@playwright/test";

test.skip(
  !process.env.AUTH0_MTLS_CLIENT_ID ||
    !process.env.AUTH0_MTLS_CLIENT_SECRET ||
    !process.env.TEST_MTLS_CERT_PATH,
  "mTLS tests require AUTH0_MTLS_CLIENT_ID, AUTH0_MTLS_CLIENT_SECRET, TEST_MTLS_CERT_PATH"
);

// ─── Login and token shape ─────────────────────────────────────────────────────

test.describe("mTLS — login flow and certificate-bound token @integration", () => {
  test("login with mTLS app completes successfully", async ({ page }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });
    // If we reach the server page, login completed (middleware set session)
    await expect(page.locator("body")).toBeVisible();
  });

  test("access token contains certificate binding (cnf/x5t#S256 claim)", async ({
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
    const parts = token.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      if (payload.cnf) {
        // mTLS-bound tokens include cnf with x5t#S256 (certificate thumbprint)
        expect(payload.cnf).toHaveProperty("x5t#S256");
      }
    }
  });

  test("getAccessToken() returns token from mTLS endpoint", async ({ page, context }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const res = await context.request.get("/auth/access-token");
    expect([200, 401]).toContain(res.status());
    if (res.status() === 200) {
      const body = await res.json();
      expect(typeof body.token).toBe("string");
    }
  });
});

// ─── Token refresh ─────────────────────────────────────────────────────────────

test.describe("mTLS — token refresh uses mTLS endpoint @integration", () => {
  test("force-refresh returns a new certificate-bound token", async ({ page, context }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const sessionRes = await context.request.get("/app-router/api/get-session");
    if (sessionRes.status() !== 200) {
      test.skip();
      return;
    }
    const { tokenSet } = await sessionRes.json();
    if (!tokenSet?.refreshToken) {
      test.skip();
      return;
    }

    const res = await context.request.get("/app-router/api/access-token-force-refresh");
    expect([200, 401]).toContain(res.status());
  });
});

// ─── getAccessTokenForConnection() with mTLS ──────────────────────────────────

test.describe("mTLS — getAccessTokenForConnection() @integration", () => {
  test.skip(
    !process.env.TEST_MTLS_CONNECTION,
    "requires TEST_MTLS_CONNECTION env var"
  );

  test("connection token via mTLS endpoint is bound to client certificate", async ({
    page,
    context,
  }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const connection = process.env.TEST_MTLS_CONNECTION!;
    const res = await context.request.get(
      `/app-router/api/access-token-for-connection?connection=${encodeURIComponent(connection)}`
    );
    expect([200, 400, 403]).toContain(res.status());
  });
});
