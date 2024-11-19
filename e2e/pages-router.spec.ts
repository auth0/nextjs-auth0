import { expect, test } from "@playwright/test"

test("getSession()", async ({ page }) => {
  await page.goto("/auth/login?returnTo=/pages-router/server")

  // fill out Auth0 form
  await page.fill('input[id="username"]', "test@example.com")
  await page.fill('input[id="password"]', process.env.TEST_USER_PASSWORD!)
  await page.getByText("Continue", { exact: true }).click()

  // check that the page says "Welcome, test@example.com!"
  expect(await page.getByRole("heading", { level: 1 }).textContent()).toBe(
    "Welcome, test@example.com!"
  )

  // ensure we're redirected back to the home page on logout
  await page.goto("/auth/logout")
  expect(await page.getByRole("heading", { level: 1 }).textContent()).toBe(
    "Home"
  )

  // check that `getSession()` returns null after logging out
  await page.goto("/pages-router/server")
  expect(page.getByRole("link", { name: "Log in" })).toBeVisible()
})

test("useUser()", async ({ page }) => {
  await page.goto("/auth/login?returnTo=/pages-router/client")

  // fill out Auth0 form
  await page.fill('input[id="username"]', "test@example.com")
  await page.fill('input[id="password"]', process.env.TEST_USER_PASSWORD!)
  await page.getByText("Continue", { exact: true }).click()

  // check that the page says "Welcome, test@example.com!"
  expect(await page.getByRole("heading", { level: 1 }).textContent()).toBe(
    "Welcome, test@example.com!"
  )

  // ensure we're redirected back to the home page on logout
  await page.goto("/auth/logout")
  expect(await page.getByRole("heading", { level: 1 }).textContent()).toBe(
    "Home"
  )

  // check that `getSession()` returns null after logging out
  await page.goto("/pages-router/client")
  expect(page.getByRole("link", { name: "Log in" })).toBeVisible()
})

test("getAccessToken()", async ({ page }) => {
  await page.goto("/auth/login?returnTo=/pages-router/client")

  // fill out Auth0 form
  await page.fill('input[id="username"]', "test@example.com")
  await page.fill('input[id="password"]', process.env.TEST_USER_PASSWORD!)
  await page.getByText("Continue", { exact: true }).click()

  // fetch a token
  const requestPromise = page.waitForRequest("/auth/access-token")
  await page.getByText("Get token").click()
  const request = await requestPromise
  const tokenRequest = await (await request.response())?.json()
  expect(tokenRequest).toHaveProperty("token")
  expect(tokenRequest).toHaveProperty("expires_at")
})

test("protected API route", async ({ page, request, context }) => {
  // before establishing a session, we should receive a 401
  const unauthedRes = await context.request.fetch("/api/pages-router/test")
  expect(unauthedRes.status()).toBe(401)

  await page.goto("/auth/login?returnTo=/pages-router/server")

  // fill out Auth0 form
  await page.fill('input[id="username"]', "test@example.com")
  await page.fill('input[id="password"]', process.env.TEST_USER_PASSWORD!)
  await page.getByText("Continue", { exact: true }).click()

  // after establishing a session, we should receive a 200
  const authedRes = await context.request.fetch("/api/pages-router/test")
  expect(authedRes.status()).toBe(200)
  expect(await authedRes.json()).toEqual({ email: "test@example.com" })
})
