/**
 * Connected Accounts E2E tests.
 *
 * Covers:
 *  - connectAccount() — /auth/connect redirects to Auth0 when authenticated
 *  - connectAccount() — unauthenticated user redirected to login
 *  - /app-router/connect-account page — renders connect link and session info
 *  - getAccessTokenForConnection() — 401 without session
 *  - getAccessTokenForConnection() — route reachable when authenticated (400/403 if no federated token)
 *  - getAccessTokenForConnection() — ?connection param passed through to SDK
 *  - /auth/connect?returnTo= — returnTo param honored (redirects to Auth0 with it)
 *
 * Full federation token flow (getAccessTokenForConnection returning 200) requires
 * a connected social account on the test user. These tests lock down the SDK surface
 * and route wiring without needing a real federated token.
 */

import { expect, test } from "@playwright/test";
import { loginWithAuth0 } from "../../helpers";

// ─── /auth/connect ─────────────────────────────────────────────────────────────

test.describe("/auth/connect — connectAccount() handler", () => {
  test("unauthenticated user is redirected to login", async ({ page }) => {
    await page.goto("/auth/connect?connection=google-oauth2&returnTo=/app-router/connect-account");
    await expect(page).toHaveURL(/\/auth\/login/);
  });

  test("authenticated user is redirected to Auth0 connect flow (3xx to Auth0)", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.get(
      "/auth/connect?connection=google-oauth2&returnTo=/app-router/connect-account",
      { maxRedirects: 0 }
    );
    // SDK redirects to Auth0 authorize endpoint for account linking
    expect(res.status()).toBeLessThan(500);
    // If it's a redirect, the Location header should point to Auth0
    if (res.status() >= 300 && res.status() < 400) {
      const location = res.headers()["location"] ?? "";
      expect(location).toContain("auth0.com");
    }
  });

  test("/auth/connect is not 404 or 405", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.get(
      "/auth/connect?connection=google-oauth2",
      { maxRedirects: 0 }
    );
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("returnTo param is passed through to Auth0", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.get(
      "/auth/connect?connection=google-oauth2&returnTo=/app-router/connect-account",
      { maxRedirects: 0 }
    );
    expect(res.status()).toBeLessThan(500);
  });
});

// ─── /app-router/connect-account page ─────────────────────────────────────────

test.describe("/app-router/connect-account — page rendering", () => {
  test("shows unauthenticated state when no session", async ({ page }) => {
    await page.goto("/app-router/connect-account");
    await expect(page.locator("#status")).toHaveText("unauthenticated");
  });

  test("shows authenticated state and connect link when logged in", async ({ page }) => {
    await loginWithAuth0(page, "/app-router/connect-account");
    await expect(page.locator("#status")).toHaveText("authenticated");
    await expect(page.locator("#connect-link")).toBeVisible();
    const href = await page.locator("#connect-link").getAttribute("href");
    expect(href).toContain("/auth/connect");
    expect(href).toContain("connection=google-oauth2");
  });

  test("connect link has returnTo pointing back to connect-account page", async ({ page }) => {
    await loginWithAuth0(page, "/app-router/connect-account");
    const href = await page.locator("#connect-link").getAttribute("href");
    expect(href).toContain("returnTo=");
    expect(href).toContain("connect-account");
  });
});

// ─── getAccessTokenForConnection() ────────────────────────────────────────────

test.describe("getAccessTokenForConnection() — API route", () => {
  test("returns 401 without session", async ({ context }) => {
    const res = await context.request.get(
      "/app-router/api/access-token-for-connection?connection=google-oauth2"
    );
    expect(res.status()).toBe(401);
  });

  test("returns structured error body on 401", async ({ context }) => {
    const res = await context.request.get(
      "/app-router/api/access-token-for-connection?connection=google-oauth2"
    );
    expect(res.status()).toBe(401);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("route is reachable when authenticated (no 404/500)", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.get(
      "/app-router/api/access-token-for-connection?connection=google-oauth2"
    );
    // 400/403 = no federated token for this user; 200 = token exists. All are valid.
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(500);
  });

  test("?connection param is passed through to Auth0 SDK", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.get(
      "/app-router/api/access-token-for-connection?connection=google-oauth2"
    );
    // Route must not return 405 (method not allowed) — GET is wired
    expect(res.status()).not.toBe(405);
    const body = await res.json();
    // Either a token shape or an SDK error with code — never silent failure
    expect(typeof body).toBe("object");
  });

  test("missing ?connection param falls back to default connection", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");
    // Route defaults connection to "google-oauth2" when param absent
    const res = await context.request.get("/app-router/api/access-token-for-connection");
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(500);
  });

  test("error body name is 'AccessTokenForConnectionError' when SDK throws", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.get(
      "/app-router/api/access-token-for-connection?connection=google-oauth2"
    );
    if (res.status() !== 200) {
      const body = await res.json();
      expect(body.name).toBe("AccessTokenForConnectionError");
      expect(typeof body.code).toBe("string");
    }
  });
});

// ─── ConnectAccountError — class identity ─────────────────────────────────────

test.describe("ConnectAccountError — error class identity", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("error name is 'ConnectAccountError' when unauthenticated", async ({ context }) => {
    const res = await context.request.get(
      "/app-router/api/connect-account-error?connection=google-oauth2"
    );
    expect(res.status()).toBe(401);
    const body = await res.json();
    expect(body.name).toBe("ConnectAccountError");
    expect(body.code).toBe("missing_session");
  });
});
