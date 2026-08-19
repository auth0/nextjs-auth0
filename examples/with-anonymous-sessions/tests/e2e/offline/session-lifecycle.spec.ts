/**
 * Offline mock-backed anonymous session suite (Tier 1: O1-O7).
 *
 * Runs against E2E_ANON_MOCK=1 server on :3001. All tokens synthetic,
 * deterministic, no tenant needed.
 */
import { expect, test } from "@playwright/test";

import { createAnon, readAnon, setScenario } from "./helpers";

test.beforeEach(async ({ context }) => {
  await setScenario(context.request, "success");
});

test("O1: create success returns session and cookie persists", async ({
  context
}) => {
  const res = await createAnon(context.request);
  expect(res.status()).toBe(201);

  const body = await res.json();
  expect(body.id).toMatch(/^anon@/);
  expect(body.accessToken).toBeTruthy();
  expect(typeof body.expiresAt).toBe("number");

  const { status, json } = await readAnon(context.request);
  expect(status).toBe(200);
  expect(json.id).toBe(body.id);
});

test("O2: create with metadata persists metadata", async ({ context }) => {
  const res = await createAnon(context.request, {
    metadata: { cart_id: "abc123" }
  });
  expect(res.status()).toBe(201);

  const { status, json } = await readAnon(context.request);
  expect(status).toBe(200);
  expect(json.metadata.cart_id).toBe("abc123");
});

test("O3: client panel renders anonymous session", async ({ context }) => {
  await createAnon(context.request);

  const page = await context.newPage();
  await page.goto("/demo");

  // Target the client-side panel under "Client-Side Session (Live)" heading
  const clientHeading = page.getByRole("heading", {
    name: "Client-Side Session (Live)"
  });
  await expect(clientHeading).toBeVisible();

  // The client panel is the .session-panel after the client heading
  const clientPanel = page
    .locator("h2:has-text('Client-Side Session (Live)')")
    .locator("xpath=following-sibling::div[contains(@class, 'session-panel')]")
    .first();

  await expect(clientPanel).toContainText(/anon@/);
});

test("O4: no session returns 204 and panel shows empty state", async ({
  context
}) => {
  // Fresh context, no create
  const { status } = await readAnon(context.request);
  expect(status).toBe(204);

  const page = await context.newPage();
  await page.goto("/demo");

  const clientPanel = page
    .locator("h2:has-text('Client-Side Session (Live)')")
    .locator("xpath=following-sibling::*")
    .first();

  await expect(clientPanel).toContainText(
    "No anonymous session found (client-side hook)"
  );
});

test("O5: metadata renders in client panel", async ({ context }) => {
  await createAnon(context.request, { metadata: { cart_id: "xyz" } });

  const page = await context.newPage();
  await page.goto("/demo");

  const clientPanel = page
    .locator("h2:has-text('Client-Side Session (Live)')")
    .locator("xpath=following-sibling::div[contains(@class, 'session-panel')]")
    .first();

  const metaPre = clientPanel.locator("pre");
  await expect(metaPre).toContainText("cart_id");
  await expect(metaPre).toContainText("xyz");
});

test("O6: guest button creates session", async ({ context }) => {
  const page = await context.newPage();
  await page.goto("/");

  const guestButton = page.getByRole("button", { name: "Enter as Guest" });
  await guestButton.click();

  // Button triggers POST /api/anon/create then redirects to /demo
  await page.waitForURL("/demo");

  // Verify client panel populated
  const clientPanel = page
    .locator("h2:has-text('Client-Side Session (Live)')")
    .locator("xpath=following-sibling::div[contains(@class, 'session-panel')]")
    .first();

  await expect(clientPanel).toContainText(/anon@/);
});

test("O7: client-side session panel resolves to the anon session", async ({
  context
}) => {
  await createAnon(context.request);

  const page = await context.newPage();
  await page.goto("/demo", { waitUntil: "domcontentloaded" });

  // We deliberately do NOT assert the transient "Loading..." text nor intercept
  // internals: /demo also renders the session server-side, and the client hook's
  // isLoading window is not deterministically observable through hydration (it
  // can resolve before a stable DOM match, and SWR may serve without a fresh
  // client fetch). The reliable, meaningful invariant is that the live
  // client-side panel (useAnonymousSession) resolves to the anon session. The
  // loading/error/data hook states are covered directly by the hook unit test
  // (src/client/hooks/use-anonymous-session.test.ts).
  const clientPanel = page
    .locator("h2:has-text('Client-Side Session (Live)')")
    .locator("xpath=following-sibling::div[contains(@class, 'session-panel')]")
    .first();

  await expect(clientPanel).toContainText(/anon@/, { timeout: 10_000 });
});

test("O-logout: logout clears cookie and redirects to home", async ({
  context
}) => {
  await createAnon(context.request);

  const page = await context.newPage();
  await page.goto("/demo");

  const clientPanel = page
    .locator("h2:has-text('Client-Side Session (Live)')")
    .locator("xpath=following-sibling::div[contains(@class, 'session-panel')]")
    .first();

  await expect(clientPanel).toContainText(/anon@/);

  const logoutButton = clientPanel.getByRole("button", { name: "Logout" });
  await logoutButton.click();

  // Should redirect to /
  await page.waitForURL("/");

  // Verify auth0_anon* cookies gone
  const cookies = await context.cookies();
  const anonCookies = cookies.filter((c) => c.name.startsWith("auth0_anon"));
  expect(anonCookies.length).toBe(0);
});
