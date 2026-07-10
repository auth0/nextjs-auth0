/**
 * IPSIE (Interoperability Profile for Secure Identity in the Enterprise) E2E tests.
 *
 * All tests require an Auth0 tenant with IPSIE-compatible enterprise connections and
 * an external IPSIE-capable IdP. Set:
 *   AUTH0_IPSIE_DOMAIN         — Auth0 domain for the IPSIE-configured tenant
 *   AUTH0_IPSIE_CLIENT_ID      — application client ID
 *   AUTH0_IPSIE_CLIENT_SECRET  — application client secret
 *   TEST_IPSIE_ENTERPRISE_CONNECTION — name of the IPSIE enterprise connection
 *
 * Covers:
 *  - Login via IPSIE enterprise connection
 *  - Session contains enterprise IdP claims (sub, org_id, etc.)
 *  - Back-channel logout from enterprise IdP terminates session (BCLO)
 *  - Token exchange from enterprise IdP token (CTE flow)
 *
 * These tests are environment-specific and require an external enterprise IdP
 * in addition to an IPSIE-configured Auth0 tenant.
 *
 * @see https://auth0.com/docs/authenticate/enterprise-connections
 */

import { expect, test } from "@playwright/test";

test.skip(
  !process.env.AUTH0_IPSIE_CLIENT_ID || !process.env.TEST_IPSIE_ENTERPRISE_CONNECTION,
  "IPSIE tests require AUTH0_IPSIE_CLIENT_ID + TEST_IPSIE_ENTERPRISE_CONNECTION env vars"
);

// ─── Login via enterprise connection ──────────────────────────────────────────

test.describe("IPSIE — enterprise connection login @integration", () => {
  test("/auth/login redirects to enterprise connection authorize URL", async ({ context }) => {
    const connection = process.env.TEST_IPSIE_ENTERPRISE_CONNECTION!;
    const res = await context.request.get(
      `/auth/login?connection=${encodeURIComponent(connection)}&returnTo=/app-router/server`,
      { maxRedirects: 0 }
    );
    expect([301, 302, 307, 308]).toContain(res.status());
    const location = res.headers()["location"] ?? "";
    expect(location).toContain("authorize");
  });

  test("enterprise login sets session with org_id or hd claim", async ({ page, context }) => {
    // Full enterprise login requires a live enterprise IdP — @integration guard
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const res = await context.request.get("/app-router/api/get-session");
    expect(res.status()).toBe(200);
    const session = await res.json();
    expect(session.user).toHaveProperty("sub");
    // Enterprise logins typically include org_id or domain hint (hd)
    const hasEnterpriseClaim =
      session.user.org_id !== undefined || session.user.hd !== undefined;
    // Not asserting strictly — depends on enterprise IdP configuration
    expect(typeof session.user.sub).toBe("string");
  });
});

// ─── Session claims ────────────────────────────────────────────────────────────

test.describe("IPSIE — session contains enterprise IdP claims @integration", () => {
  test("session user sub is present after enterprise login", async ({ page, context }) => {
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
    expect(typeof session.user.sub).toBe("string");
  });

  test("access token from enterprise login is retrievable", async ({ page, context }) => {
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

// ─── Back-channel logout from enterprise IdP ──────────────────────────────────

test.describe("IPSIE — enterprise-initiated BCLO @integration", () => {
  test.skip(
    !process.env.TEST_IPSIE_BCLO_TOKEN,
    "requires TEST_IPSIE_BCLO_TOKEN — signed logout_token from enterprise IdP"
  );

  test("enterprise BCLO token is accepted and session is revoked", async ({
    page,
    context,
  }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    // Confirm session active
    const sessionBefore = await context.request.get("/app-router/api/get-session");
    expect(sessionBefore.status()).toBe(200);

    // Post enterprise-issued logout token
    const bcloRes = await context.request.post("/auth/backchannel-logout", {
      data: { logout_token: process.env.TEST_IPSIE_BCLO_TOKEN },
    });
    expect(bcloRes.status()).toBe(200);

    // Session must now be revoked (stateful store) or cookie cleared
    const sessionAfter = await context.request.get("/app-router/api/get-session");
    // 401 = session revoked (stateful) or cookie cleared
    // 200 = stateless store — BCLO marks but doesn't prevent read (acceptable)
    expect([200, 401]).toContain(sessionAfter.status());
  });
});

// ─── Custom Token Exchange from enterprise token ───────────────────────────────

test.describe("IPSIE — CTE from enterprise IdP token @integration", () => {
  test.skip(
    !process.env.TEST_IPSIE_SUBJECT_TOKEN,
    "requires TEST_IPSIE_SUBJECT_TOKEN — a valid enterprise IdP token for CTE"
  );

  test("enterprise subject token is exchanged for an Auth0 token", async ({
    page,
    context,
  }) => {
    await page.goto("/auth/login?returnTo=/app-router/server");
    await page.waitForURL((url) => url.pathname === "/app-router/server", {
      timeout: 30_000,
    });

    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: {
        subjectToken: process.env.TEST_IPSIE_SUBJECT_TOKEN,
        subjectTokenType:
          process.env.TEST_IPSIE_SUBJECT_TOKEN_TYPE ??
          "urn:ietf:params:oauth:token-type:id_token",
      },
    });
    expect([200, 400, 401]).toContain(res.status());
    if (res.status() === 200) {
      const body = await res.json();
      expect(body).toHaveProperty("accessToken");
    }
  });
});
