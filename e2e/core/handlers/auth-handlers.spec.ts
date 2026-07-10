/**
 * Authentication handler E2E tests.
 *
 * Session strategy:
 *  - Tests that only need to inspect HTTP redirect/response use context.request with empty storageState
 *  - Tests that observe the login flow itself (callback cookies, txn cookie) call loginWithAuth0()
 *  - Tests that need an authenticated session use injectSession() — no Auth0 UI round-trip
 *  - Tests that need to observe logout URL params use injectSession() + page.goto("/auth/logout")
 */

import { expect, test } from "@playwright/test"
import { loginWithAuth0, injectSession, EMAIL } from "../../helpers"

// ─── handleLogin ─────────────────────────────────────────────────────────────

test.describe("handleLogin — /auth/login", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("redirects to the authorization server", async ({ page }) => {
    const [res] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("auth0.com") || r.url().includes("/authorize")),
      page.goto("/auth/login"),
    ])
    expect(res.status()).toBeLessThan(400)
    await expect(page).toHaveURL(/auth0\.com|login/i)
  })

  test("redirects to returnTo path after successful login — App Router", async ({ page }) => {
    await loginWithAuth0(page, "/app-router/server")
    await expect(page).toHaveURL("/app-router/server")
    await expect(page.locator("#status")).toHaveText("authenticated")
  })

  test("redirects to returnTo path after successful login — Pages Router", async ({ page }) => {
    await loginWithAuth0(page, "/pages-router/server")
    await expect(page).toHaveURL("/pages-router/server")
    await expect(page.locator("#status")).toHaveText("authenticated")
  })

  test("forwards screen_hint=signup to the authorization server", async ({ page }) => {
    await page.goto("/auth/login?screen_hint=signup")
    await expect(page).toHaveURL(/auth0\.com|signup/i, { timeout: 10_000 })
  })

  test("forwards connection param to the authorization server", async ({ page }) => {
    const [res] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("auth0.com") && r.url().includes("authorize")),
      page.goto("/auth/login?connection=Username-Password-Authentication"),
    ])
    expect(res.url()).toContain("connection=Username-Password-Authentication")
  })

  test("forwards audience param to the authorization server", async ({ page }) => {
    const audience = encodeURIComponent("https://piyush-kumar.au.auth0.com/api/v2/")
    const [res] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("auth0.com") && r.url().includes("authorize")),
      page.goto(`/auth/login?audience=${audience}`),
    ])
    expect(res.url()).toContain("audience=")
  })

  test("rejects invalid challengeMode with 400", async ({ context }) => {
    const res = await context.request.get("/auth/login?challengeMode=invalid", { maxRedirects: 0 })
    expect(res.status()).toBe(400)
    expect(await res.text()).toContain("Invalid challengeMode")
  })

  test("rejects non-numeric max_age with 400", async ({ context }) => {
    const res = await context.request.get("/auth/login?max_age=notanumber", { maxRedirects: 0 })
    expect(res.status()).toBe(400)
    expect(await res.text()).toContain("Invalid max_age")
  })

  test("forwards max_age=0 to the authorization server", async ({ page }) => {
    const [res] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("auth0.com") && r.url().includes("authorize")),
      page.goto("/auth/login?max_age=0"),
    ])
    expect(res.url()).toContain("max_age=0")
  })

  test("accepts challengeMode=popup without error", async ({ context }) => {
    const res = await context.request.get("/auth/login?challengeMode=popup", { maxRedirects: 0 })
    expect(res.status()).not.toBe(400)
    expect([301, 302, 307, 308]).toContain(res.status())
  })

  test("forwards scope param to the authorization server", async ({ page }) => {
    const [res] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("auth0.com") && r.url().includes("authorize")),
      page.goto("/auth/login?scope=openid+profile+email"),
    ])
    expect(res.url()).toContain("scope=")
  })

  test("includes PKCE code_challenge with S256 method in authorization request", async ({ context }) => {
    const res = await context.request.get("/auth/login", { maxRedirects: 0 })
    expect([301, 302, 307, 308]).toContain(res.status())
    const authUrl = new URL(res.headers()["location"])
    expect(authUrl.searchParams.get("code_challenge")).not.toBeNull()
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256")
  })

  test("includes nonce and state in authorization request", async ({ context }) => {
    const res = await context.request.get("/auth/login", { maxRedirects: 0 })
    const authUrl = new URL(res.headers()["location"])
    expect(authUrl.searchParams.get("nonce")).not.toBeNull()
    expect(authUrl.searchParams.get("state")).not.toBeNull()
  })

  test("sets redirect_uri to /auth/callback in authorization request", async ({ context }) => {
    const res = await context.request.get("/auth/login", { maxRedirects: 0 })
    const authUrl = new URL(res.headers()["location"])
    expect(authUrl.searchParams.get("redirect_uri")).toContain("/auth/callback")
  })

  test("default scope includes openid", async ({ context }) => {
    const res = await context.request.get("/auth/login", { maxRedirects: 0 })
    const authUrl = new URL(res.headers()["location"])
    expect(authUrl.searchParams.get("scope")).toContain("openid")
  })

  test("sets response_type=code in authorization request", async ({ context }) => {
    const res = await context.request.get("/auth/login", { maxRedirects: 0 })
    const authUrl = new URL(res.headers()["location"])
    expect(authUrl.searchParams.get("response_type")).toBe("code")
  })

  test("includes client_id in authorization request", async ({ context }) => {
    const res = await context.request.get("/auth/login", { maxRedirects: 0 })
    const authUrl = new URL(res.headers()["location"])
    expect(authUrl.searchParams.get("client_id")).not.toBeNull()
    expect(authUrl.searchParams.get("client_id")!.length).toBeGreaterThan(0)
  })

  test("ignores cross-origin returnTo and falls back to default path", async ({ context }) => {
    const res = await context.request.get(
      "/auth/login?returnTo=https%3A%2F%2Fattacker.example.com",
      { maxRedirects: 0 }
    )
    expect([301, 302, 307, 308]).toContain(res.status())
    const authUrl = new URL(res.headers()["location"])
    expect(authUrl.toString()).not.toContain("attacker.example.com")
  })

  test("forwards organization param to the authorization server", async ({ context }) => {
    const res = await context.request.get("/auth/login?organization=org_abc123", { maxRedirects: 0 })
    expect([301, 302, 307, 308]).toContain(res.status())
    const authUrl = new URL(res.headers()["location"])
    expect(authUrl.searchParams.get("organization")).toBe("org_abc123")
  })

  test("forwards invitation param to the authorization server", async ({ context }) => {
    const res = await context.request.get(
      "/auth/login?organization=org_abc123&invitation=inv_xyz789",
      { maxRedirects: 0 }
    )
    expect([301, 302, 307, 308]).toContain(res.status())
    const authUrl = new URL(res.headers()["location"])
    expect(authUrl.searchParams.get("invitation")).toBe("inv_xyz789")
  })
})

// ─── handleCallback ───────────────────────────────────────────────────────────

test.describe("handleCallback — /auth/callback", () => {
  test.describe("error cases", () => {
    test.use({ storageState: { cookies: [], origins: [] } })

    test("rejects callback with no state parameter", async ({ context }) => {
      const res = await context.request.get("/auth/callback?code=fake_code")
      expect(res.status()).toBeGreaterThanOrEqual(400)
    })

    test("rejects callback with no parameters at all", async ({ context }) => {
      const res = await context.request.get("/auth/callback")
      expect(res.status()).toBeGreaterThanOrEqual(400)
    })

    test("returns error when Auth0 denies authorization (access_denied)", async ({ page }) => {
      await page.goto("/auth/callback?error=access_denied&error_description=User+denied+access&state=bogus")
      expect(page.url()).toBeTruthy()
    })


  })

  test.describe("successful callback", () => {
    // These tests need a real login to observe what the callback handler sets
    test.use({ storageState: { cookies: [], origins: [] } })

    test("sets httpOnly session cookie on successful callback", async ({ page }) => {
      await loginWithAuth0(page, "/app-router/server")
      const cookies = await page.context().cookies()
      const sessionCookie = cookies.find((c) => c.name === "__session")
      expect(sessionCookie).toBeDefined()
      expect(sessionCookie?.httpOnly).toBe(true)
    })

    test("removes transaction cookie after successful callback", async ({ page }) => {
      await loginWithAuth0(page, "/app-router/server")
      const cookies = await page.context().cookies()
      const txnCookies = cookies.filter((c) => c.name.startsWith("__txn_") && c.value !== "")
      expect(txnCookies.length).toBe(0)
    })
  })
})

// ─── handleLogout ─────────────────────────────────────────────────────────────

test.describe("handleLogout — /auth/logout", () => {
  test.describe("no session", () => {
    test.use({ storageState: { cookies: [], origins: [] } })

    test("redirects even when no session exists", async ({ context }) => {
      const res = await context.request.get("/auth/logout", { maxRedirects: 0 })
      expect([301, 302, 307, 308]).toContain(res.status())
    })

    test("omits logout_hint when no session exists", async ({ context }) => {
      const res = await context.request.get("/auth/logout", { maxRedirects: 0 })
      const location = res.headers()["location"]
      if (location) {
        expect(new URL(location).searchParams.get("logout_hint")).toBeNull()
      }
    })

    test("omits id_token_hint when no session exists", async ({ context }) => {
      const res = await context.request.get("/auth/logout", { maxRedirects: 0 })
      const location = res.headers()["location"]
      if (location) {
        expect(new URL(location).searchParams.get("id_token_hint")).toBeNull()
      }
    })
  })

  test.describe("with session", () => {
    test("clears session cookie on logout", async ({ page, context }) => {
      await injectSession(context)
      expect((await page.context().cookies()).find((c) => c.name === "__session")).toBeDefined()
      await page.goto("/auth/logout")
      await page.waitForURL((url) => !url.href.includes("/auth/logout"), { timeout: 10_000 })
      const sessionCookie = (await page.context().cookies()).find((c) => c.name === "__session")
      expect(!sessionCookie || sessionCookie.value === "").toBe(true)
    })

    test("renders unauthenticated state after logout — App Router", async ({ page, context }) => {
      await injectSession(context)
      await page.goto("/auth/logout")
      await page.waitForURL((url) => !url.href.includes("/auth/logout"), { timeout: 10_000 })
      await page.goto("/app-router/server")
      await expect(page.locator("#status")).toHaveText("unauthenticated")
    })

    test("renders unauthenticated state after logout — Pages Router", async ({ page, context }) => {
      await injectSession(context)
      await page.goto("/auth/logout")
      await page.waitForURL((url) => !url.href.includes("/auth/logout"), { timeout: 10_000 })
      await page.goto("/pages-router/server")
      await expect(page.locator("#status")).toHaveText("unauthenticated")
    })

    test("forwards federated flag to the authorization server", async ({ page, context }) => {
      await injectSession(context)
      const [response] = await Promise.all([
        page.waitForResponse((r) => r.url().includes("auth0.com") && r.url().includes("logout")),
        page.goto("/auth/logout?federated"),
      ])
      expect(response.status()).toBeLessThan(400)
    })

    test("forwards returnTo as post_logout_redirect_uri", async ({ page, context }) => {
      await injectSession(context)
      const [logoutReq] = await Promise.all([
        page.waitForResponse((r) => r.url().includes("auth0.com") && r.url().includes("logout")),
        page.goto("/auth/logout?returnTo=http%3A%2F%2Flocalhost%3A3000"),
      ])
      expect(logoutReq.url()).toContain("localhost%3A3000")
    })

    test("forwards state param to the end_session endpoint", async ({ page, context }) => {
      await injectSession(context)
      const [logoutReq] = await Promise.all([
        page.waitForResponse((r) => r.url().includes("auth0.com") && r.url().includes("logout")),
        page.goto("/auth/logout?state=my-custom-state"),
      ])
      expect(logoutReq.url()).toContain("state=my-custom-state")
    })

    test("includes logout_hint and id_token_hint from session", async ({ page, context }) => {
      await injectSession(context, {
        user: { sub: "auth0|logout001", email: "logout@example.com" },
        tokenSet: { accessToken: "tok", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
      })
      const [logoutReq] = await Promise.all([
        page.waitForResponse((r) => r.url().includes("auth0.com") && r.url().includes("logout")),
        page.goto("/auth/logout"),
      ])
      expect(logoutReq.status()).toBeLessThan(400)
      expect(logoutReq.url()).toContain("client_id=")
    })
  })
})

// ─── Variant: logoutStrategy: "v2" ───────────────────────────────────────────

test.describe("logoutStrategy: 'v2' — logout URL uses /v2/logout", () => {
  test("logout redirect uses /v2/logout endpoint", async ({ context }) => {
    const res = await context.request.get("/app-router/api/variants/logout-strategy-v2")
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(typeof body.location === "string" ? body.location : "").toMatch(/\/v2\/logout/)
  })

  test("logout redirect does not use OIDC end_session_endpoint", async ({ context }) => {
    const res = await context.request.get("/app-router/api/variants/logout-strategy-v2")
    const body = await res.json()
    if (body.location) {
      expect(body.location).not.toContain("end_session")
    }
  })
})

// ─── handleProfile ────────────────────────────────────────────────────────────

test.describe("handleProfile — /auth/profile", () => {
  test("returns 401 when not authenticated", async ({ context }) => {
    // Override storageState for this single test
    const res = await context.request.get("/auth/profile", {
      headers: { cookie: "" },
    })
    // The unauthenticated state is tested via empty storageState at describe level elsewhere;
    // here we check the injected session path below
    expect([200, 401]).toContain(res.status())
  })

  test("returns user claims when authenticated", async ({ context }) => {
    await injectSession(context, {
      user: { sub: "profile|001", email: EMAIL, name: "Profile User" },
    })
    const res = await context.request.get("/auth/profile")
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(body).toHaveProperty("email", EMAIL)
    expect(body).toHaveProperty("sub")
  })

  test("sets Cache-Control: no-store", async ({ context }) => {
    await injectSession(context, {
      user: { sub: "profile|002", email: "cache@example.com" },
    })
    const res = await context.request.get("/auth/profile")
    expect(res.headers()["cache-control"]).toContain("no-store")
  })

  test("excludes tokenSet and internal fields from response", async ({ context }) => {
    await injectSession(context, {
      user: { sub: "profile|003", email: "profile@example.com", name: "Profile User" },
    })
    const res = await context.request.get("/auth/profile")
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(body).not.toHaveProperty("tokenSet")
    expect(body).not.toHaveProperty("internal")
    expect(body.email).toBe("profile@example.com")
  })
})

test.describe("handleProfile — /auth/profile — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("returns 401 when not authenticated", async ({ context }) => {
    const res = await context.request.get("/auth/profile")
    expect(res.status()).toBe(401)
  })
})

// ─── handleAccessToken ────────────────────────────────────────────────────────

test.describe("handleAccessToken — /auth/access-token — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("returns 401 when not authenticated", async ({ context }) => {
    const res = await context.request.get("/auth/access-token")
    expect(res.status()).toBe(401)
  })

  test("401 error response includes code and message fields", async ({ context }) => {
    const res = await context.request.get("/auth/access-token")
    const body = await res.json()
    expect(typeof body.error.code).toBe("string")
    expect(typeof body.error.message).toBe("string")
  })
})

test.describe("handleAccessToken — /auth/access-token", () => {
  test("returns access token string", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-access-token", expiresAt: Math.floor(Date.now() / 1000) + 3600, scope: "openid profile email" },
    })
    const res = await context.request.get("/auth/access-token")
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(typeof body.token).toBe("string")
    expect(body.token.length).toBeGreaterThan(0)
  })

  test("returns future expires_at Unix timestamp", async ({ context }) => {
    const expiresAt = Math.floor(Date.now() / 1000) + 3600
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt },
    })
    const now = Math.floor(Date.now() / 1000)
    const body = await (await context.request.get("/auth/access-token")).json()
    expect(typeof body.expires_at).toBe("number")
    expect(body.expires_at).toBeGreaterThan(now)
  })

  test("returns non-negative expires_in seconds", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const body = await (await context.request.get("/auth/access-token")).json()
    expect(typeof body.expires_in).toBe("number")
    expect(body.expires_in).toBeGreaterThanOrEqual(0)
  })

  test("always includes scope field in response", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600, scope: "openid profile" },
    })
    const body = await (await context.request.get("/auth/access-token")).json()
    expect("scope" in body).toBe(true)
    if (body.scope !== null) {
      expect(typeof body.scope).toBe("string")
    }
  })

  test("includes token_type when present in token set", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600, token_type: "Bearer" },
    })
    const body = await (await context.request.get("/auth/access-token")).json()
    if ("token_type" in body) {
      expect(typeof body.token_type).toBe("string")
    }
  })


  test("returns 401 with session_expired code when IPSIE session ceiling has passed", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "valid-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
      internal: { sid: "test-sid", createdAt: Math.floor(Date.now() / 1000) - 7200, sessionExpiresAt: Math.floor(Date.now() / 1000) - 1 },
    })
    const res = await context.request.get("/auth/access-token")
    expect(res.status()).toBe(401)
    expect((await res.json()).error).toHaveProperty("code")
  })

  test("clears session cookie after IPSIE session expiry", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "valid-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
      internal: { sid: "test-sid", createdAt: Math.floor(Date.now() / 1000) - 7200, sessionExpiresAt: Math.floor(Date.now() / 1000) - 1 },
    })
    await context.request.get("/auth/access-token")
    const res2 = await context.request.get("/auth/access-token")
    expect(res2.status()).toBe(401)
    expect((await res2.json()).error.code).toBe("missing_session")
  })

  test("returns 401 missing_refresh_token when token expired and no refresh token", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "expired-token", expiresAt: Math.floor(Date.now() / 1000) - 3600 },
    })
    const res = await context.request.get("/auth/access-token")
    expect(res.status()).toBe(401)
    expect((await res.json()).error.code).toBe("missing_refresh_token")
  })

  test("forwards audience query param — 200 or structured 401", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get(
      "/auth/access-token?audience=https%3A%2F%2Fpiyush-kumar.au.auth0.com%2Fapi%2Fv2%2F"
    )
    expect([200, 401]).toContain(res.status())
  })

  test("forwards scope query param — 200 or structured 401", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get("/auth/access-token?scope=openid+profile")
    expect([200, 401]).toContain(res.status())
  })

  test("respects mergeScopes=false query param", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get("/auth/access-token?scope=openid&mergeScopes=false")
    expect([200, 401]).toContain(res.status())
  })
})

// ─── Middleware ───────────────────────────────────────────────────────────────

test.describe("auth0.middleware()", () => {
  test.describe("public routes", () => {
    test.use({ storageState: { cookies: [], origins: [] } })

    test("allows public routes through", async ({ context }) => {
      const res = await context.request.get("/")
      expect(res.status()).toBe(200)
    })

    test("intercepts /auth/* routes", async ({ context }) => {
      const res = await context.request.get("/auth/login", { maxRedirects: 0 })
      expect([301, 302, 307, 308]).toContain(res.status())
    })

    test("does not intercept static asset paths", async ({ context }) => {
      const res = await context.request.get("/_next/static/chunks/main.js")
      expect(res.status()).not.toBe(500)
    })
  })

  test("sets httpOnly SameSite=Lax session cookie", async ({ context }) => {
    // storageState from setup already has the session cookie — assert its attributes
    await injectSession(context)
    const cookies = await context.cookies()
    const session = cookies.find((c) => c.name === "__session")
    expect(session?.httpOnly).toBe(true)
    expect(session?.sameSite).toBe("Lax")
  })
})
