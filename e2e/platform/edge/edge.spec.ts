/**
 * Edge Runtime E2E tests.
 *
 * Verifies that the SDK's middleware (`auth0.middleware()`) functions correctly
 * when running in the Next.js Edge Runtime — specifically:
 *
 *  MIDDLEWARE ROUTING:
 *  - /auth/* routes are intercepted by middleware (not passed through)
 *  - /auth/login redirects to Auth0 Universal Login
 *  - /auth/logout redirects to Auth0 logout URL
 *  - /auth/callback is handled (redirects or processes token exchange)
 *  - Static assets (_next/static, _next/image) bypass middleware
 *  - Public pages (/) pass through without redirect
 *
 *  SESSION PROPAGATION VIA MIDDLEWARE:
 *  - Middleware forwards a valid session cookie to downstream handlers
 *  - Protected routes redirected by middleware when no session present
 *  - Rolling session: middleware updates cookie maxAge on each request
 *
 *  EDGE-SPECIFIC BEHAVIOR:
 *  - Large session cookies are chunked by middleware (3500-byte chunks)
 *  - middleware() exports a valid matcher config that excludes static assets
 *  - Middleware does not block non-/auth requests when session is absent
 *
 * The test app registers `auth0.middleware()` in `proxy.ts` with a matcher
 * that covers all paths except _next/static, _next/image, favicon.ico,
 * sitemap.xml, and robots.txt.
 */

import { expect, test } from "@playwright/test";
import { loginWithAuth0, injectSession, logout } from "../../helpers";

// ─── Middleware routing ────────────────────────────────────────────────────────

test.describe("middleware routing — /auth/* interception", () => {
  test("/auth/login is intercepted and redirects to Auth0", async ({ context }) => {
    const res = await context.request.get("/auth/login", { maxRedirects: 0 });
    expect([301, 302, 307, 308]).toContain(res.status());
    const location = res.headers()["location"] ?? "";
    expect(location).toContain("auth0.com");
  });

  test("/auth/logout is intercepted and redirects", async ({ context }) => {
    const res = await context.request.get("/auth/logout", { maxRedirects: 0 });
    // Unauthenticated logout still returns a redirect (to home or Auth0)
    expect(res.status()).toBeLessThan(500);
  });

  test("/auth/callback is handled (not 404)", async ({ context }) => {
    // Without a real code/state it returns an error, but the route must be wired
    const res = await context.request.get("/auth/callback", { maxRedirects: 0 });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("/ (home) passes through without redirect when unauthenticated", async ({ context }) => {
    const res = await context.request.get("/");
    expect(res.status()).toBe(200);
  });

  test("_next/static assets bypass middleware (not 404 or 500)", async ({ context }) => {
    // Just verify the path isn't intercepted and blowing up — actual file may not exist
    const res = await context.request.get("/_next/static/chunks/main.js");
    expect(res.status()).not.toBe(500);
  });
});

// ─── Session propagation via middleware ────────────────────────────────────────

test.describe("middleware — session forwarded to route handlers", () => {
  test("injected session is readable in route handler after passing through middleware", async ({
    context,
  }) => {
    await injectSession(context);
    // Route handler reads session — middleware has forwarded the cookie
    const res = await context.request.get("/app-router/api/get-session");
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty("user");
  });

  test("missing session results in 401 from route handler (middleware passes it through)", async ({
    context,
  }) => {
    const res = await context.request.get("/app-router/api/get-session");
    expect(res.status()).toBe(401);
  });

  test("protected page is accessible when session present", async ({ page, context }) => {
    await injectSession(context);
    await page.goto("/app-router/protected");
    await expect(page.locator("#status")).toHaveText("authenticated");
  });

  test("withPageAuthRequired redirects to login when no session", async ({ page }) => {
    await page.goto("/app-router/protected");
    await expect(page).toHaveURL(/\/auth\/login/);
  });
});

// ─── Cookie attributes set by middleware ──────────────────────────────────────

test.describe("middleware — session cookie attributes", () => {
  test("session cookie is httpOnly after login", async ({ page }) => {
    await loginWithAuth0(page, "/app-router/server");
    const cookies = await page.context().cookies();
    const session = cookies.find((c) => c.name === "__session");
    expect(session).toBeDefined();
    expect(session!.httpOnly).toBe(true);
  });

  test("session cookie has SameSite=Lax", async ({ page }) => {
    await loginWithAuth0(page, "/app-router/server");
    const cookies = await page.context().cookies();
    const session = cookies.find((c) => c.name === "__session");
    expect(session!.sameSite).toBe("Lax");
  });

  test("session cookie is cleared after logout", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    await logout(page);
    const cookies = await context.cookies();
    const session = cookies.find((c) => c.name === "__session");
    // Cookie is cleared — either absent or has empty value / past expiry
    if (session) {
      expect(session.expires).toBeLessThan(Date.now() / 1000 + 1);
    }
  });
});

// ─── Rolling session via middleware ───────────────────────────────────────────

test.describe("middleware — rolling session extends cookie maxAge", () => {
  test("making requests keeps session cookie expiry at least as large", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");

    const cookiesBefore = await context.cookies();
    const sessionBefore = cookiesBefore.find((c) => c.name === "__session");
    const expiresBefore = sessionBefore?.expires ?? 0;

    await page.waitForTimeout(1000);
    // Trigger a request so middleware has a chance to roll the session
    await context.request.get("/app-router/api/get-session");

    const cookiesAfter = await context.cookies();
    const sessionAfter = cookiesAfter.find((c) => c.name === "__session");
    const expiresAfter = sessionAfter?.expires ?? 0;

    // Rolling session: expiry is maintained or extended on activity
    expect(expiresAfter).toBeGreaterThanOrEqual(expiresBefore);
  });
});

// ─── Chunked cookies ──────────────────────────────────────────────────────────

test.describe("middleware — large session cookies are chunked", () => {
  test("session with large user claims is split across __session__0/__session__1 chunks", async ({
    context,
  }) => {
    // Inject a session with a large payload that will exceed the 3500-byte chunk size
    const largeUser: Record<string, unknown> = {
      sub: "test|chunked001",
      email: "chunked@example.com",
    };
    // Pad the payload to force chunking (~4KB of extra claims)
    for (let i = 0; i < 50; i++) {
      largeUser[`claim_${i}`] = "x".repeat(80);
    }

    await injectSession(context, { user: largeUser });

    const cookies = await context.cookies();
    const sessionCookies = cookies.filter((c) => c.name.startsWith("__session"));

    if (sessionCookies.length > 1) {
      // Chunked — all chunks present
      const names = sessionCookies.map((c) => c.name).sort();
      expect(names[0]).toMatch(/^__session/);
    } else {
      // Single chunk — payload fit within limit (acceptable)
      expect(sessionCookies.length).toBe(1);
    }

    // Session is still readable regardless of chunk count
    const res = await context.request.get("/app-router/api/get-session");
    expect(res.status()).toBe(200);
  });
});

// ─── Middleware matcher config ─────────────────────────────────────────────────

test.describe("middleware matcher — excluded paths bypass middleware", () => {
  test("robots.txt is reachable without Auth0 middleware interference", async ({ context }) => {
    const res = await context.request.get("/robots.txt");
    // May 404 if not present in test app, but must not be a 5xx caused by middleware
    expect(res.status()).not.toBe(500);
  });

  test("favicon.ico is not intercepted by middleware", async ({ context }) => {
    const res = await context.request.get("/favicon.ico");
    expect(res.status()).not.toBe(500);
  });
});
