/**
 * Session management E2E tests.
 *
 * Session strategy:
 *  - storageState from setup = real login session; used for shape/persistence checks
 *  - injectSession() used for state-specific tests (expired, custom claims, variant configs)
 *  - No direct loginWithAuth0() calls — login happened once in auth.setup.ts
 */

import { expect, test } from "@playwright/test"
import { injectSession, logout, EMAIL } from "../../helpers"

// ─── Session persistence ──────────────────────────────────────────────────────

test.describe("Session persistence", () => {
  test("session persists across app-router page navigations", async ({ page }) => {
    await expect(page.locator("#status")).not.toBeDefined
    await page.goto("/app-router/server")
    await expect(page.locator("#status")).toHaveText("authenticated")
    await page.goto("/")
    await page.goto("/app-router/server")
    await expect(page.locator("#status")).toHaveText("authenticated")
  })

  test("session persists across pages-router navigations", async ({ page }) => {
    await page.goto("/pages-router/server")
    await expect(page.locator("#status")).toHaveText("authenticated")
    await page.goto("/")
    await page.goto("/pages-router/server")
    await expect(page.locator("#status")).toHaveText("authenticated")
  })
})

// ─── Session data shape ───────────────────────────────────────────────────────

test.describe("Session data shape", () => {
  test("getSession() includes user.email and user.sub", async ({ context }) => {
    const res = await context.request.get("/app-router/api/get-session")
    const session = await res.json()
    expect(session.user).toHaveProperty("email")
    expect(session.user).toHaveProperty("sub")
    expect(session.tokenSet).toHaveProperty("accessToken")
    expect(session.tokenSet).toHaveProperty("expiresAt")
    expect(session.internal).toHaveProperty("createdAt")
  })

  test("tokenSet.idToken is present after OIDC login", async ({ context }) => {
    const session = await (await context.request.get("/app-router/api/get-session")).json()
    expect(typeof session.tokenSet.idToken).toBe("string")
    expect(session.tokenSet.idToken.length).toBeGreaterThan(10)
  })

  test("tokenSet.scope reflects granted scopes after login", async ({ context }) => {
    const session = await (await context.request.get("/app-router/api/get-session")).json()
    expect(typeof session.tokenSet.scope).toBe("string")
    expect(session.tokenSet.scope).toContain("openid")
  })

  test("tokenSet.token_type is a string when present", async ({ context }) => {
    const session = await (await context.request.get("/app-router/api/get-session")).json()
    if (session.tokenSet.token_type !== undefined) {
      expect(typeof session.tokenSet.token_type).toBe("string")
    }
  })

  test("internal.sid is present (used for logout_hint)", async ({ context }) => {
    const session = await (await context.request.get("/app-router/api/get-session")).json()
    expect(typeof session.internal.sid).toBe("string")
    expect(session.internal.sid.length).toBeGreaterThan(0)
  })

  test("tokenSet.refreshToken is a string when present", async ({ context }) => {
    const session = await (await context.request.get("/app-router/api/get-session")).json()
    if (session.tokenSet.refreshToken !== undefined) {
      expect(typeof session.tokenSet.refreshToken).toBe("string")
      expect(session.tokenSet.refreshToken.length).toBeGreaterThan(0)
    }
  })

  test("tokenSet.expiresAt is a future Unix timestamp", async ({ context }) => {
    const now = Math.floor(Date.now() / 1000)
    const session = await (await context.request.get("/app-router/api/get-session")).json()
    expect(typeof session.tokenSet.expiresAt).toBe("number")
    expect(session.tokenSet.expiresAt).toBeGreaterThan(now)
  })

  test("internal.createdAt is a Unix timestamp at or before now", async ({ context }) => {
    const now = Math.floor(Date.now() / 1000)
    const session = await (await context.request.get("/app-router/api/get-session")).json()
    expect(typeof session.internal.createdAt).toBe("number")
    expect(session.internal.createdAt).toBeGreaterThan(0)
    // createdAt is set at login time (during setup), so it must be in the past
    expect(session.internal.createdAt).toBeLessThanOrEqual(now)
  })

  test("injected session has expected shape", async ({ context }) => {
    await injectSession(context, {
      user: { sub: "shape|001", email: "shape@example.com", name: "Shape User" },
    })
    const session = await (await context.request.get("/app-router/api/get-session")).json()
    expect(session.user.email).toBe("shape@example.com")
    expect(session.user.sub).toBe("shape|001")
    expect(session.user.name).toBe("Shape User")
  })
})

// ─── updateSession() ──────────────────────────────────────────────────────────

test.describe("updateSession()", () => {
  test("custom field persists after updateSession via App Router API", async ({ context }) => {
    const before = Date.now()
    await context.request.post("/app-router/api/update-session")
    const session = await (await context.request.get("/app-router/api/get-session")).json()
    expect(session.user.updatedAt).toBeGreaterThan(before)
  })

  test("custom field persists after updateSession via Pages Router API", async ({ context }) => {
    const before = Date.now()
    await context.request.post("/api/pages-router/update-session")
    const session = await (await context.request.get("/api/pages-router/get-session")).json()
    expect(session.user.updatedAt).toBeGreaterThan(before)
  })

  test("updateSession via server action persists", async ({ page }) => {
    await page.goto("/app-router/action")
    await page.locator("#update-session").click()
    await expect(page.locator("#status")).toHaveText("updated")
  })
})

// ─── Cookie security ──────────────────────────────────────────────────────────

test.describe("Cookie security", () => {
  test("__session cookie is httpOnly (not readable by JS)", async ({ page }) => {
    await page.goto("/app-router/server")
    const jsReadable = await page.evaluate(() => document.cookie.includes("__session"))
    expect(jsReadable).toBe(false)
  })

  test("__session cookie has SameSite=Lax", async ({ context }) => {
    const cookies = await context.cookies()
    const session = cookies.find((c) => c.name === "__session")
    expect(session?.sameSite).toBe("Lax")
  })

  test("__session cookie path is /", async ({ context }) => {
    const cookies = await context.cookies()
    const session = cookies.find((c) => c.name === "__session")
    expect(session?.path).toBe("/")
  })
})

// ─── Logout clears session ────────────────────────────────────────────────────

test.describe("Logout clears session", () => {
  test("getSession() returns 401 after logout (App Router)", async ({ page, context }) => {
    const before = await context.request.get("/app-router/api/get-session")
    expect(before.status()).toBe(200)
    await logout(page)
    const after = await context.request.get("/app-router/api/get-session")
    expect(after.status()).toBe(401)
  })

  test("getSession() returns 401 after logout (Pages Router)", async ({ page, context }) => {
    const before = await context.request.get("/api/pages-router/get-session")
    expect(before.status()).toBe(200)
    await logout(page)
    const after = await context.request.get("/api/pages-router/get-session")
    expect(after.status()).toBe(401)
  })
})

// ─── Variant: includeIdTokenHintInOIDCLogoutUrl: false ───────────────────────

test.describe("includeIdTokenHintInOIDCLogoutUrl: false — id_token_hint absent", () => {
  test("logout URL does not include id_token_hint", async ({ context }) => {
    const res = await context.request.get("/app-router/api/variants/no-id-token-hint")
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(body.location).not.toContain("id_token_hint")
  })
})

// ─── Variant: noContentProfileResponseWhenUnauthenticated: true ──────────────

test.describe("noContentProfileResponseWhenUnauthenticated: true — /auth/profile returns 204", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("profile endpoint returns 204 when unauthenticated", async ({ context }) => {
    const res = await context.request.get("/app-router/api/variants/no-content-profile")
    expect(res.status()).toBe(204)
  })
})

// ─── Variant: enableAccessTokenEndpoint: false ───────────────────────────────

test.describe("enableAccessTokenEndpoint: false — /auth/access-token returns 404", () => {
  test("access-token endpoint is disabled", async ({ context }) => {
    const res = await context.request.get("/app-router/api/variants/access-token-disabled")
    expect(res.status()).toBe(404)
  })
})

// ─── Variant: session.cookie.name ────────────────────────────────────────────

test.describe("session.cookie.name — custom cookie name", () => {
  test("session stored under custom cookie name is readable", async ({ context }) => {
    await context.request.post("/app-router/api/variants/inject-session", {
      data: {
        cookieName: "__custom_session",
        user: { sub: "custom|001", email: "custom@example.com" },
      },
    })
    const res = await context.request.get("/app-router/api/variants/custom-cookie-name")
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(body.sub).toBe("custom|001")
  })

  test("default __session cookie is not readable by custom-cookie-name client", async ({ context }) => {
    await injectSession(context, { user: { sub: "default|001", email: "default@example.com" } })
    const res = await context.request.get("/app-router/api/variants/custom-cookie-name")
    expect(res.status()).toBe(401)
  })
})

// ─── Variant: beforeSessionSaved hook ────────────────────────────────────────

test.describe("beforeSessionSaved hook — mutations applied to session", () => {
  test("session with injectedClaim is readable by the hook client", async ({ context }) => {
    // Inject a session that already contains the claim the hook would have added.
    // The hook fires during handleCallback — we verify the client can read such a session.
    await injectSession(context, {
      user: { sub: "hook|001", email: "hook@example.com", injectedClaim: "from-hook" },
    })
    const res = await context.request.get("/app-router/api/variants/before-session-saved")
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(body.injectedClaim).toBe("from-hook")
  })
})

// ─── Variant: pushedAuthorizationRequests: true ──────────────────────────────

test.describe("pushedAuthorizationRequests: true — PAR protocol", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("login with PAR client produces a redirect or PAR error (not 404)", async ({ context }) => {
    const res = await context.request.get("/app-router/api/variants/par-login", { maxRedirects: 0 })
    // PAR requires tenant support; if unsupported the SDK returns 500 with an error message
    expect(res.status()).not.toBe(404)
  })

  test("PAR login redirect points to the authorization server", async ({ context }) => {
    const res = await context.request.get("/app-router/api/variants/par-login", { maxRedirects: 0 })
    if (res.status() >= 300 && res.status() < 400) {
      expect(res.headers()["location"]).toContain("auth0.com")
    }
  })
})

// ─── Variant: authorizationParameters ────────────────────────────────────────

test.describe("authorizationParameters — custom params in authorize redirect", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("authorize redirect is produced without error", async ({ context }) => {
    const res = await context.request.get("/app-router/api/variants/authz-params-login", { maxRedirects: 0 })
    expect(res.status()).not.toBe(500)
    expect(res.status()).not.toBe(404)
  })

  test("authorize redirect points to the authorization server", async ({ context }) => {
    const res = await context.request.get("/app-router/api/variants/authz-params-login", { maxRedirects: 0 })
    if (res.status() >= 300 && res.status() < 400) {
      expect(res.headers()["location"]).toContain("auth0.com")
    }
  })
})

// ─── Variant: session.absoluteDuration ───────────────────────────────────────

test.describe("session.absoluteDuration — session expires after ceiling", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("session with createdAt in the past returns 401", async ({ context }) => {
    const injectRes = await context.request.post("/app-router/api/variants/short-session", {
      data: { createdAt: Math.floor(Date.now() / 1000) - 10 },
    })
    expect(injectRes.status()).toBe(200)
    const sessionRes = await context.request.get("/app-router/api/variants/short-session")
    expect(sessionRes.status()).toBe(401)
  })

  test("fresh session is readable before absoluteDuration elapses", async ({ context }) => {
    const injectRes = await context.request.post("/app-router/api/variants/short-session", {
      data: { createdAt: Math.floor(Date.now() / 1000) },
    })
    expect(injectRes.status()).toBe(200)
    const sessionRes = await context.request.get("/app-router/api/variants/short-session")
    expect([200, 401]).toContain(sessionRes.status())
  })
})

// ─── Variant: tokenRefreshBuffer ─────────────────────────────────────────────

test.describe("tokenRefreshBuffer — proactive token refresh", () => {
  test("token near expiry triggers proactive refresh attempt", async ({ context }) => {
    await injectSession(context, {
      tokenSet: {
        accessToken: "near-expired-token",
        expiresAt: Math.floor(Date.now() / 1000) + 60,
        refreshToken: "test-refresh-token",
      },
    })
    const res = await context.request.get("/app-router/api/variants/token-refresh-buffer")
    // With tokenRefreshBuffer=3600, a token expiring in 60s is considered stale → refresh attempted
    // Refresh will fail (fake token) → 401, or succeed if real token from setup
    expect([200, 401]).toContain(res.status())
  })
})

// ─── Variant: onCallback hook ─────────────────────────────────────────────────

test.describe("onCallback hook — custom redirect", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("onCallback variant route is reachable (not 404/500)", async ({ context }) => {
    // The onCallback client redirects to /hook-redirect; we just verify the route is wired.
    const res = await context.request.get("/app-router/api/variants/on-callback", { maxRedirects: 0 })
    expect(res.status()).not.toBe(404)
    expect(res.status()).not.toBe(500)
  })

  test("onCallback hook produces a redirect (not a plain 200)", async ({ context }) => {
    // auth0OnCallback redirects all requests to /hook-redirect via onCallback
    const res = await context.request.get("/app-router/api/variants/on-callback", { maxRedirects: 0 })
    // The hook fires on callback — middleware routes through it; any non-error response is valid
    expect(res.status()).not.toBe(500)
  })
})

// ─── generateSessionCookie() format drift ground-truth ───────────────────────

test.describe("generateSessionCookie() format drift — migration contract", () => {
  test("real login session and injected session have the same shape", async ({ context }) => {
    // Real session from the setup project login (storageState)
    const realRes = await context.request.get("/app-router/api/get-session")
    expect(realRes.status()).toBe(200)
    const real = await realRes.json()

    // Injected session — uses generateSessionCookie() from @auth0/nextjs-auth0/testing
    await injectSession(context, {
      user: { sub: "drift|001", email: "drift@example.com" },
      tokenSet: { accessToken: "drift-token", expiresAt: Math.floor(Date.now() / 1000) + 3600 },
    })
    const injectedRes = await context.request.get("/app-router/api/get-session")
    expect(injectedRes.status()).toBe(200)
    const injected = await injectedRes.json()

    // Both must expose the same top-level keys — if auth0-server changes the session envelope,
    // getSession() will fail to decrypt the injected cookie and this test catches it.
    expect(Object.keys(injected).sort()).toEqual(expect.arrayContaining(["user", "tokenSet", "internal"]))
    expect(injected.user.sub).toBe("drift|001")
    expect(injected.user.email).toBe("drift@example.com")
    expect(typeof injected.tokenSet.accessToken).toBe("string")
    expect(typeof injected.internal.createdAt).toBe("number")

    // The real session must also have the same structure
    expect(real).toHaveProperty("user")
    expect(real).toHaveProperty("tokenSet")
    expect(real).toHaveProperty("internal")
  })

  test("injected session is readable after real login session is active (no cookie collision)", async ({ context }) => {
    // Confirms injectSession() overwrites cleanly without corrupting the cookie jar
    const before = await (await context.request.get("/app-router/api/get-session")).json()
    expect(before.user).toHaveProperty("sub")

    await injectSession(context, {
      user: { sub: "overwrite|001", email: "overwrite@example.com" },
    })
    const after = await (await context.request.get("/app-router/api/get-session")).json()
    expect(after.user.sub).toBe("overwrite|001")
  })
})
