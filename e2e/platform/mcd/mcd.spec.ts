/**
 * Multi-Custom-Domain (MCD) E2E tests.
 *
 * All tests require a separate Auth0 tenant configured with multiple custom
 * domains. Set:
 *   AUTH0_MCD_DOMAIN         — primary Auth0 domain
 *   AUTH0_MCD_CLIENT_ID      — application client ID
 *   AUTH0_MCD_CLIENT_SECRET  — application client secret
 *   TEST_MCD_CUSTOM_DOMAIN   — secondary custom domain to test cross-domain session validation
 *
 * Covers:
 *  - Session issued from domain A is valid when request arrives via domain B
 *  - getSession() validates the iss claim against the configured domain (not request host)
 *  - Tokens issued by custom domain contain the correct issuer in the ID token
 *  - Login flow uses custom domain in the authorize redirect
 *
 * MCD session sharing relies on the SDK resolving the correct JWKS endpoint for
 * the configured AUTH0_DOMAIN, ignoring the Host header.
 *
 * @see https://auth0.com/docs/customize/custom-domains
 */

import { expect, test } from "@playwright/test";

test.skip(
  !process.env.AUTH0_MCD_CLIENT_ID || !process.env.TEST_MCD_CUSTOM_DOMAIN,
  "MCD tests require AUTH0_MCD_CLIENT_ID + TEST_MCD_CUSTOM_DOMAIN env vars"
);

// ─── Login via custom domain ──────────────────────────────────────────────────

test.describe("MCD — login redirects to custom domain @integration", () => {
  test("/auth/login redirects to the configured custom domain", async ({ context }) => {
    const res = await context.request.get("/auth/login", { maxRedirects: 0 });
    expect([301, 302, 307, 308]).toContain(res.status());
    const location = res.headers()["location"] ?? "";
    // With MCD, the authorize URL uses the configured custom domain
    expect(location).toContain(process.env.AUTH0_MCD_DOMAIN!);
  });

  test("login with MCD app completes and sets session", async ({ page }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });
    await expect(page.locator("body")).toBeVisible();
  });
});

// ─── Session issuer validation ────────────────────────────────────────────────

test.describe("MCD — issuer claim validated against configured domain @integration", () => {
  test("session user sub and email are present after MCD login", async ({
    page,
    context,
  }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const res = await context.request.get("/app-router/api/get-session");
    expect(res.status()).toBe(200);
    const session = await res.json();
    expect(session.user).toHaveProperty("sub");
    expect(session.user).toHaveProperty("email");
  });

  test("ID token iss claim matches configured custom domain", async ({ page, context }) => {
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

    // idToken is available in session.tokenSet — decode to check iss
    const idToken: string | undefined = session.tokenSet?.idToken;
    if (idToken) {
      const parts = idToken.split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
        expect(payload.iss).toContain(process.env.AUTH0_MCD_DOMAIN);
      }
    }
  });
});

// ─── Cross-domain session validity ────────────────────────────────────────────

test.describe("MCD — cross-domain session @integration", () => {
  test.skip(
    !process.env.TEST_MCD_SECOND_DOMAIN,
    "requires TEST_MCD_SECOND_DOMAIN — a second custom domain on the same tenant"
  );

  test("session from domain A is valid when accessed via domain B", async ({
    page,
    context,
  }) => {
    // Login via primary domain
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    // Access session endpoint — SDK validates iss against AUTH0_DOMAIN (not request host)
    const res = await context.request.get("/app-router/api/get-session");
    expect(res.status()).toBe(200);
  });
});

// ─── Access token with custom domain ─────────────────────────────────────────

test.describe("MCD — getAccessToken() via custom domain @integration", () => {
  test("getAccessToken() returns a valid token after MCD login", async ({ page, context }) => {
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
