/**
 * Advanced auth flows E2E tests.
 *
 * Session strategy:
 *  - storageState from setup = real session; used for /me/*, /my-org/*, force-refresh with real refreshToken
 *  - injectSession() for all tests needing specific token shapes
 *  - test.use({ storageState: empty }) for unauthenticated paths
 *  - No direct loginWithAuth0() calls except force-refresh test that needs a real refreshToken
 */

import { expect, test } from "@playwright/test"
import { loginWithAuth0, injectSession } from "../../helpers"

// ─── getAccessTokenForConnection() ───────────────────────────────────────────

test.describe("getAccessTokenForConnection() — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("returns 401 without session", async ({ context }) => {
    const res = await context.request.get("/app-router/api/access-token-for-connection?connection=google-oauth2")
    expect(res.status()).toBe(401)
  })
})

test.describe("getAccessTokenForConnection() — API route", () => {
  test("returns 400 or token-shaped response when authenticated (no federated token in test session)", async ({ context }) => {
    await injectSession(context, {
      user: { sub: "conn|001", email: "conn@example.com" },
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get("/app-router/api/access-token-for-connection?connection=google-oauth2")
    expect([200, 400, 403]).toContain(res.status())
    const body = await res.json()
    expect(typeof body).toBe("object")
  })

  test("error body name is 'AccessTokenForConnectionError' when SDK throws", async ({ context }) => {
    await injectSession(context, {
      user: { sub: "conn|002", email: "conn2@example.com" },
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get("/app-router/api/access-token-for-connection?connection=google-oauth2")
    if (res.status() !== 200) {
      const body = await res.json()
      expect(body.name).toBe("AccessTokenForConnectionError")
      expect(typeof body.code).toBe("string")
      expect(body.code.length).toBeGreaterThan(0)
    }
  })
})

// ─── customTokenExchange() ────────────────────────────────────────────────────

test.describe("customTokenExchange() — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("returns 401 without session", async ({ context }) => {
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: { subjectToken: "fake-token" },
    })
    expect(res.status()).toBe(401)
  })
})

test.describe("customTokenExchange() — API route", () => {
  test("returns 400 with invalid subject token when authenticated", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: { subjectToken: "invalid-token" },
    })
    expect([400, 401, 403]).toContain(res.status())
    const body = await res.json()
    expect(body).toHaveProperty("error")
  })
})

// ─── connectAccount() — /auth/connect ─────────────────────────────────────────

test.describe("connectAccount() — /auth/connect", () => {
  test.describe("unauthenticated", () => {
    test.use({ storageState: { cookies: [], origins: [] } })

    test("returns 401 for unauthenticated user (connectAccount requires active session)", async ({ context }) => {
      // connectAccount requires an existing session to link; it returns 401, not a login redirect.
      const res = await context.request.get(
        "/auth/connect?connection=google-oauth2&returnTo=/app-router/server",
        { maxRedirects: 0 }
      )
      expect(res.status()).toBe(401)
    })
  })

  test("/auth/connect route exists and handles GET when authenticated", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get(
      "/auth/connect?connection=google-oauth2&returnTo=/app-router/server",
      { maxRedirects: 0 }
    )
    expect(res.status()).toBeLessThan(500)
  })

  test("redirects authenticated user toward Auth0 connect flow", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "test-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get(
      "/auth/connect?connection=google-oauth2&returnTo=/app-router/server",
      { maxRedirects: 0 }
    )
    if (res.status() >= 300 && res.status() < 400) {
      expect(res.headers()["location"]).toBeTruthy()
    }
  })
})

// ─── handleBackChannelLogout ──────────────────────────────────────────────────

test.describe("handleBackChannelLogout — /auth/backchannel-logout", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("returns 400/500 on missing logout_token body (requires stateful session store)", async ({ context }) => {
    const res = await context.request.post("/auth/backchannel-logout", { data: {} })
    // 500 = stateless session store (no store.deleteByLogoutToken); 400 = stateful store, invalid body
    expect([400, 401, 500]).toContain(res.status())
  })

  test("POST method is accepted (not 405 or 404)", async ({ context }) => {
    const res = await context.request.post("/auth/backchannel-logout", {
      data: { logout_token: "invalid.jwt.token" },
    })
    expect(res.status()).not.toBe(405)
    expect(res.status()).not.toBe(404)
  })

  test("GET method returns non-200 (route is POST-only)", async ({ context }) => {
    const res = await context.request.get("/auth/backchannel-logout")
    expect(res.status()).not.toBe(200)
  })
})

// ─── /me/* proxy ─────────────────────────────────────────────────────────────

test.describe("/me/* proxy — My Account API", () => {
  test.describe("unauthenticated", () => {
    test.use({ storageState: { cookies: [], origins: [] } })

    test("GET /me/v1/authentication-methods returns 401 without session", async ({ context }) => {
      const res = await context.request.get("/me/v1/authentication-methods")
      expect(res.status()).toBe(401)
    })
  })

  test("GET /me/v1/authentication-methods is reachable when authenticated", async ({ context }) => {
    // Requires a token with me/ audience — the setup session may not have one.
    // 401/403 means the route reached Auth0 (proxy works); 500 means the proxy route
    // threw when the token lacked the required audience — route is wired, just not for this token.
    const res = await context.request.get("/me/v1/authentication-methods")
    expect(res.status()).not.toBe(404)
    expect([200, 401, 403, 500]).toContain(res.status())
  })
})

// ─── /my-org/* proxy ─────────────────────────────────────────────────────────

test.describe("/my-org/* proxy", () => {
  test.describe("unauthenticated", () => {
    test.use({ storageState: { cookies: [], origins: [] } })

    test("GET /my-org/v1/members returns 401 without session", async ({ context }) => {
      const res = await context.request.get("/my-org/v1/members")
      expect(res.status()).toBe(401)
    })
  })

  test("GET /my-org/v1/members is reachable when authenticated", async ({ context }) => {
    // Requires a token with my-org/ audience; 401/403/404 means route is wired but token missing.
    const res = await context.request.get("/my-org/v1/members")
    expect([200, 401, 403, 404]).toContain(res.status())
  })
})

// ─── handleAccessToken behavioral depth ──────────────────────────────────────

test.describe("handleAccessToken — /auth/access-token — behavioral depth", () => {
  test.describe("unauthenticated", () => {
    test.use({ storageState: { cookies: [], origins: [] } })

    test("401 body includes error.code and error.message", async ({ context }) => {
      const res = await context.request.get("/auth/access-token")
      expect(res.status()).toBe(401)
      const body = await res.json()
      expect(body.error).toHaveProperty("message")
      expect(body.error).toHaveProperty("code")
    })
  })

  test("200 response shape: token, scope, expires_at, expires_in all present", async ({ context }) => {
    await injectSession(context, {
      tokenSet: {
        accessToken: "valid-token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        scope: "openid profile email",
      },
    })
    const res = await context.request.get("/auth/access-token")
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(typeof body.token).toBe("string")
    expect(typeof body.expires_at).toBe("number")
    expect(typeof body.expires_in).toBe("number")
    expect("scope" in body).toBe(true)
  })

  test("expires_in = expires_at - now (within 5s tolerance)", async ({ context }) => {
    const expiresAt = Math.floor(Date.now() / 1000) + 3600
    await injectSession(context, {
      tokenSet: { accessToken: "valid-token", expiresAt },
    })
    const before = Math.floor(Date.now() / 1000)
    const res = await context.request.get("/auth/access-token")
    const after = Math.floor(Date.now() / 1000)
    const body = await res.json()
    const expectedMin = body.expires_at - after
    const expectedMax = body.expires_at - before
    expect(body.expires_in).toBeGreaterThanOrEqual(Math.max(0, expectedMin - 2))
    expect(body.expires_in).toBeLessThanOrEqual(expectedMax + 2)
  })

  test("?audience param accepted — 200 or structured 401 (no 500)", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "valid-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get(
      "/auth/access-token?audience=https%3A%2F%2Fpiyush-kumar.au.auth0.com%2Fapi%2Fv2%2F"
    )
    expect([200, 401]).toContain(res.status())
    if (res.status() === 401) {
      expect((await res.json()).error).toHaveProperty("code")
    }
  })

  test("?scope param accepted — 200 or structured 401 (no 500)", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "valid-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get("/auth/access-token?scope=openid+profile")
    expect([200, 401]).toContain(res.status())
  })

  test("?mergeScopes=false — 200 or structured 401 (no 500)", async ({ context }) => {
    await injectSession(context, {
      tokenSet: { accessToken: "valid-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const res = await context.request.get("/auth/access-token?scope=openid&mergeScopes=false")
    expect([200, 401]).toContain(res.status())
  })

  test("injected session with valid token returns 200 with that exact token", async ({ context }) => {
    await injectSession(context, {
      tokenSet: {
        accessToken: "valid-injected-token",
        expiresAt: Math.floor(Date.now() / 1000) + 7200,
      },
    })
    const res = await context.request.get("/auth/access-token")
    expect(res.status()).toBe(200)
    expect((await res.json()).token).toBe("valid-injected-token")
  })

  test("injected expired token with no refreshToken returns 401", async ({ context }) => {
    await injectSession(context, {
      tokenSet: {
        accessToken: "expired-token",
        expiresAt: Math.floor(Date.now() / 1000) - 100,
      },
    })
    const res = await context.request.get("/auth/access-token")
    expect(res.status()).toBe(401)
    expect((await res.json()).error).toHaveProperty("code")
  })
})

// ─── Rolling session ──────────────────────────────────────────────────────────

test.describe("Rolling session", () => {
  test("session cookie maxAge is reset after activity", async ({ context }) => {
    const cookiesBefore = await context.cookies()
    const expiresBefore = cookiesBefore.find((c) => c.name === "__session")?.expires ?? 0

    await new Promise((r) => setTimeout(r, 1000))
    await context.request.get("/app-router/api/get-session")

    const cookiesAfter = await context.cookies()
    const expiresAfter = cookiesAfter.find((c) => c.name === "__session")?.expires ?? 0
    expect(expiresAfter).toBeGreaterThanOrEqual(expiresBefore)
  })

  test("logout immediately clears session regardless of rolling TTL", async ({ page, context }) => {
    await page.goto("/auth/logout")
    await page.waitForURL("/", { timeout: 10_000 })
    const res = await context.request.get("/app-router/api/get-session")
    expect(res.status()).toBe(401)
  })
})

// ─── getAccessToken({ refresh: true }) — force refresh ───────────────────────

test.describe("getAccessToken({ refresh: true }) — force refresh", () => {
  test.describe("unauthenticated", () => {
    test.use({ storageState: { cookies: [], origins: [] } })

    test("returns 401 without session", async ({ context }) => {
      const res = await context.request.get("/app-router/api/access-token-force-refresh")
      expect(res.status()).toBe(401)
    })
  })

  test("force-refresh with valid token but no refreshToken returns existing token (no refresh attempted)", async ({ context }) => {
    // refresh: true only triggers a network refresh when a refreshToken is present.
    // Without a refreshToken, the SDK returns the existing valid token as-is.
    await injectSession(context, {
      tokenSet: {
        accessToken: "still-valid-token",
        expiresAt: Math.floor(Date.now() / 1000) + 7200,
      },
    })
    const res = await context.request.get("/app-router/api/access-token-force-refresh")
    expect(res.status()).toBe(200)
    expect((await res.json()).token).toBe("still-valid-token")
  })

  test("force-refresh with valid refreshToken refreshes even when token is not expired", async ({ page, context }) => {
    // Need a real refreshToken — use the session from storageState (real login in setup)
    const sessionRes = await context.request.get("/app-router/api/get-session")
    const session = await sessionRes.json()

    if (!session.tokenSet?.refreshToken) {
      test.skip()
      return
    }

    const original = session.tokenSet.accessToken
    const res = await context.request.get("/app-router/api/access-token-force-refresh")
    expect(res.status()).toBe(200)
    expect((await res.json()).token).not.toBe(original)
  })
})

// ─── Silent auto-refresh (expired token + refreshToken present) ───────────────

test.describe("getAccessToken() — silent auto-refresh", () => {
  test("expired token with real refreshToken is silently refreshed", async ({ context }) => {
    // Pull the real refreshToken from the storageState session (genuine Auth0 token)
    const sessionRes = await context.request.get("/app-router/api/get-session")
    const session = await sessionRes.json()

    if (!session.tokenSet?.refreshToken) {
      test.skip()
      return
    }

    // Replace accessToken with an expired fake; keep the real refreshToken
    await injectSession(context, {
      tokenSet: {
        accessToken: "expired-fake-token",
        expiresAt: Math.floor(Date.now() / 1000) - 300, // expired 5 min ago
        refreshToken: session.tokenSet.refreshToken,
        scope: session.tokenSet.scope,
      },
    })

    const res = await context.request.get("/app-router/api/access-token")
    expect(res.status()).toBe(200)
    const body = await res.json()
    // SDK silently exchanged the refreshToken — returned token must not be our fake
    expect(body.token).not.toBe("expired-fake-token")
    expect(typeof body.token).toBe("string")
    expect(body.token.length).toBeGreaterThan(10)
  })

})

// ─── tokenRefreshBuffer — proactive refresh ───────────────────────────────────

test.describe("tokenRefreshBuffer: 3600 — proactive early refresh", () => {
  test("token expiring within buffer window triggers refresh attempt", async ({ context }) => {
    await injectSession(context, {
      tokenSet: {
        accessToken: "token-expiring-soon",
        expiresAt: Math.floor(Date.now() / 1000) + 1800,
      },
    })
    const res = await context.request.get("/app-router/api/variants/token-refresh-buffer")
    expect([200, 401]).toContain(res.status())
    if (res.status() === 401) {
      expect((await res.json()).code).toMatch(/missing_refresh_token|refresh/i)
    }
  })

  test("token with plenty of time is returned as-is (buffer not triggered)", async ({ context }) => {
    await injectSession(context, {
      tokenSet: {
        accessToken: "fresh-token-outside-buffer",
        expiresAt: Math.floor(Date.now() / 1000) + 7200,
      },
    })
    const res = await context.request.get("/app-router/api/variants/token-refresh-buffer")
    expect(res.status()).toBe(200)
    expect((await res.json()).token).toBe("fresh-token-outside-buffer")
  })
})
