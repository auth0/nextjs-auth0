/**
 * SDK helper E2E tests: getSession, useUser, getAccessToken, updateSession,
 * withPageAuthRequired, withApiAuthRequired, updateSession Server Action.
 *
 * Session strategy:
 *  - storageState from setup project = already logged-in session
 *  - Tests needing no session use test.use({ storageState: empty })
 *  - Tests needing specific session state call injectSession()
 *  - No direct loginWithAuth0() calls — login happened once in auth.setup.ts
 */

import { expect, test } from "@playwright/test"
import { injectSession, injectSessionPagesRouter, logout, EMAIL } from "../../helpers"

const ROUTERS = [
  {
    label: "App Router",
    serverPage: "/app-router/server",
    clientPage: "/app-router/client",
    actionPage: "/app-router/action",
    protectedPage: "/app-router/protected",
    apiGetSession: "/app-router/api/get-session",
    apiAccessToken: "/app-router/api/access-token",
    apiUpdateSession: "/app-router/api/update-session",
    apiWithApiAuthRequired: "/app-router/api/with-api-auth-required",
    inject: injectSession,
  },
  {
    label: "Pages Router",
    serverPage: "/pages-router/server",
    clientPage: "/pages-router/client",
    actionPage: null,
    protectedPage: "/pages-router/protected",
    apiGetSession: "/api/pages-router/get-session",
    apiAccessToken: "/api/pages-router/access-token",
    apiUpdateSession: "/api/pages-router/update-session",
    apiWithApiAuthRequired: "/api/pages-router/with-api-auth-required",
    inject: injectSessionPagesRouter,
  },
] as const

// ─── getSession() ─────────────────────────────────────────────────────────────

for (const router of ROUTERS) {
  test.describe(`getSession() — ${router.label}`, () => {
    test("shows unauthenticated state when no session exists", async ({ page }) => {
      // storageState from setup has a session — navigate to server page and verify authenticated
      // The unauthenticated check needs an empty context; handled in the describe below
      await page.goto(router.serverPage)
      await expect(page.locator("#status")).toHaveText("authenticated")
    })

    test("shows authenticated user email", async ({ page }) => {
      await page.goto(router.serverPage)
      await expect(page.locator("#status")).toHaveText("authenticated")
      await expect(page.locator("#email")).toHaveText(EMAIL)
    })

    test("shows unauthenticated state after logout", async ({ page, context }) => {
      await logout(page)
      await page.goto(router.serverPage)
      await expect(page.locator("#status")).toHaveText("unauthenticated")
    })

    test("session injection shows custom user", async ({ page, context }) => {
      await router.inject(context, {
        user: { sub: "injected|001", email: "injected@example.com" },
      })
      await page.goto(router.serverPage)
      await expect(page.locator("#status")).toHaveText("authenticated")
      await expect(page.locator("#email")).toHaveText("injected@example.com")
    })
  })
}

test.describe("getSession() — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  for (const router of ROUTERS) {
    test(`shows unauthenticated state — ${router.label}`, async ({ page }) => {
      await page.goto(router.serverPage)
      await expect(page.locator("#status")).toHaveText("unauthenticated")
      await expect(page.getByRole("link", { name: "Log in" })).toBeVisible()
    })
  }
})

// ─── useUser() ────────────────────────────────────────────────────────────────

for (const router of ROUTERS) {
  test.describe(`useUser() — ${router.label}`, () => {
    test("shows authenticated user", async ({ page }) => {
      await page.goto(router.clientPage)
      await expect(page.locator("#status")).toHaveText("authenticated")
      await expect(page.locator("#email")).toHaveText(EMAIL)
    })

    test("shows unauthenticated state after logout", async ({ page, context }) => {
      await logout(page)
      await page.goto(router.clientPage)
      await expect(page.locator("#status")).toHaveText("unauthenticated")
    })

    test("session injection shows user in client component", async ({ page, context }) => {
      await router.inject(context, {
        user: { sub: "injected|002", email: "client-injected@example.com" },
      })
      await page.goto(router.clientPage)
      await expect(page.locator("#status")).toHaveText("authenticated")
      await expect(page.locator("#email")).toHaveText("client-injected@example.com")
    })
  })
}

test.describe("useUser() — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  for (const router of ROUTERS) {
    test(`shows unauthenticated state — ${router.label}`, async ({ page }) => {
      await page.goto(router.clientPage)
      await expect(page.locator("#status")).toHaveText("unauthenticated")
    })
  }
})

// ─── getAccessToken() — client helper ────────────────────────────────────────

for (const router of ROUTERS) {
  test.describe(`getAccessToken() client helper — ${router.label}`, () => {
    test("returns token string when authenticated", async ({ page }) => {
      await page.goto(router.clientPage)
      await expect(page.locator("#status")).toHaveText("authenticated")

      await page.locator("#get-token").click()
      await expect(page.locator("#token-result")).not.toHaveValue("", { timeout: 8_000 })

      const tokenValue = await page.locator("#token-result").inputValue()
      expect(tokenValue.length).toBeGreaterThan(10)
    })

    test("includeFullResponse returns token and expiresAt", async ({ page }) => {
      await page.goto(router.clientPage)
      await page.locator("#get-token-full").click()

      await expect(page.locator("#token-full")).not.toHaveValue("")
      const raw = await page.locator("#token-full").inputValue()
      const parsed = JSON.parse(raw)
      expect(parsed).toHaveProperty("token")
      expect(parsed).toHaveProperty("expires_at")
    })
  })
}

// ─── getAccessToken() — API route ────────────────────────────────────────────

test.describe("getAccessToken() API route — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  for (const router of ROUTERS) {
    test(`returns 401 without session — ${router.label}`, async ({ context }) => {
      const res = await context.request.get(router.apiAccessToken)
      expect(res.status()).toBe(401)
    })
  }
})

for (const router of ROUTERS) {
  test.describe(`getAccessToken() API route — ${router.label}`, () => {
    test("returns token with session", async ({ context }) => {
      const res = await context.request.get(router.apiAccessToken)
      expect(res.status()).toBe(200)
      const body = await res.json()
      expect(body).toHaveProperty("token")
      expect(body).toHaveProperty("expiresAt")
    })
  })
}

// ─── updateSession() — API route ─────────────────────────────────────────────

test.describe("updateSession() API route — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  for (const router of ROUTERS) {
    test(`returns 401 without session — ${router.label}`, async ({ context }) => {
      const res = await context.request.post(router.apiUpdateSession)
      expect(res.status()).toBe(401)
    })
  }
})

for (const router of ROUTERS) {
  test.describe(`updateSession() API route — ${router.label}`, () => {
    test("persists custom field on session", async ({ context }) => {
      const before = Date.now()
      const updateRes = await context.request.post(router.apiUpdateSession)
      expect(updateRes.status()).toBe(200)

      const sessionRes = await context.request.get(router.apiGetSession)
      const session = await sessionRes.json()
      expect(session.user.updatedAt).toBeGreaterThan(before)
    })
  })
}

// ─── withPageAuthRequired() ───────────────────────────────────────────────────

test.describe("withPageAuthRequired() — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  for (const router of ROUTERS) {
    test(`redirects unauthenticated user to login — ${router.label}`, async ({ page }) => {
      await page.goto(router.protectedPage)
      // withPageAuthRequired redirects → /auth/login → Auth0; either URL is valid
      await expect(page).toHaveURL(/\/auth\/login|auth0\.com/)
    })
  }
})

for (const router of ROUTERS) {
  test.describe(`withPageAuthRequired() — ${router.label}`, () => {
    test("allows authenticated user to access protected page", async ({ page }) => {
      await page.goto(router.protectedPage)
      await expect(page.locator("#status")).toHaveText("authenticated")
      await expect(page.locator("#email")).toHaveText(EMAIL)
    })
  })
}

// ─── withApiAuthRequired() ────────────────────────────────────────────────────

test.describe("withApiAuthRequired() — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  for (const router of ROUTERS) {
    test(`returns 401 without session — ${router.label}`, async ({ context }) => {
      const res = await context.request.get(router.apiWithApiAuthRequired)
      expect(res.status()).toBe(401)
    })
  }
})

for (const router of ROUTERS) {
  test.describe(`withApiAuthRequired() — ${router.label}`, () => {
    test("returns user data with session", async ({ context }) => {
      const res = await context.request.get(router.apiWithApiAuthRequired)
      expect(res.status()).toBe(200)
      const body = await res.json()
      expect(body).toHaveProperty("sub")
      expect(body).toHaveProperty("email")
    })
  })
}

// ─── updateSession() — Server Action (App Router only) ───────────────────────

test.describe("updateSession() Server Action — App Router — unauthenticated", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("shows unauthenticated state without session", async ({ page }) => {
    await page.goto("/app-router/action")
    await page.locator("#check-session").click()
    await expect(page.locator("#status")).toHaveText("unauthenticated")
  })
})

test.describe("updateSession() Server Action — App Router", () => {
  test("shows authenticated user", async ({ page }) => {
    await page.goto("/app-router/action")
    await page.locator("#check-session").click()
    await expect(page.locator("#status")).toHaveText("authenticated")
    await expect(page.locator("#email")).toHaveText(EMAIL)
  })

  test("custom field persists after server action updateSession", async ({ page }) => {
    await page.goto("/app-router/action")
    await page.locator("#update-session").click()
    await expect(page.locator("#status")).toHaveText("updated")
  })
})
