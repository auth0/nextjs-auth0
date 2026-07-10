import { Page, BrowserContext } from "@playwright/test";

const EMAIL = process.env.TEST_USER_EMAIL!;
const PASSWORD = process.env.TEST_USER_PASSWORD!;

/**
 * Log in via Auth0 Universal Login UI and wait for redirect back to the app.
 */
export async function loginWithAuth0(page: Page, returnTo: string) {
  await page.goto(`/auth/login?returnTo=${encodeURIComponent(returnTo)}`);

  // Step 1: enter email/identifier and click Continue
  await page.waitForSelector('input[id="username"]', { timeout: 15_000 });
  await page.fill('input[id="username"]', EMAIL);
  await page.locator('button[data-action-button-primary="true"]').click();

  // Step 2: password field appears after identifier-first step
  await page.waitForSelector('input[id="password"]', { timeout: 15_000 });
  await page.fill('input[id="password"]', PASSWORD);
  await page.locator('button[data-action-button-primary="true"]').click();

  // After password submit, Auth0 may redirect to passkey enrollment before the app
  await page.waitForURL(
    (url) => url.href.includes(returnTo) || url.pathname === returnTo || url.href.includes("passkey-enrollment"),
    { timeout: 10_000 }
  );

  if (page.url().includes("passkey-enrollment")) {
    await page.getByRole("button", { name: /continue without passkey/i }).click();
    await page.waitForURL((url) => url.href.includes(returnTo) || url.pathname === returnTo, {
      timeout: 15_000,
    });
  }
}

/**
 * Inject a pre-built session cookie directly (no Auth0 UI, no network round-trip).
 * Accepts optional overrides for user and tokenSet fields.
 */
export async function injectSession(
  context: BrowserContext,
  opts: {
    user?: Record<string, unknown>;
    tokenSet?: Record<string, unknown>;
    internal?: Record<string, unknown>;
    apiPath?: string;
  } = {}
) {
  const apiPath = opts.apiPath ?? "/app-router/api/inject-session";
  const res = await context.request.post(apiPath, {
    data: {
      user: opts.user,
      tokenSet: opts.tokenSet,
      internal: opts.internal,
    },
  });
  if (!res.ok()) {
    throw new Error(`injectSession failed: ${res.status()} ${await res.text()}`);
  }
}

/** Inject session via the Pages Router endpoint */
export async function injectSessionPagesRouter(
  context: BrowserContext,
  opts: { user?: Record<string, unknown>; tokenSet?: Record<string, unknown>; internal?: Record<string, unknown> } = {}
) {
  return injectSession(context, {
    ...opts,
    apiPath: "/api/pages-router/inject-session",
  });
}

/** Log in via the stateful Auth0Client (writes to SQLite session store). */
export async function loginWithStatefulAuth0(page: Page, returnTo: string) {
  await loginWithAuth0Page(page, `/auth/stateful/login?returnTo=${encodeURIComponent(returnTo)}`);
}

async function loginWithAuth0Page(page: Page, loginUrl: string) {
  await page.goto(loginUrl);

  await page.waitForSelector('input[id="username"]', { timeout: 15_000 });
  await page.fill('input[id="username"]', EMAIL);
  await page.locator('button[data-action-button-primary="true"]').click();

  await page.waitForSelector('input[id="password"]', { timeout: 15_000 });
  await page.fill('input[id="password"]', PASSWORD);
  await page.locator('button[data-action-button-primary="true"]').click();

  await page.waitForURL(
    (url) => !url.href.includes("/auth/") || url.href.includes("passkey-enrollment"),
    { timeout: 10_000 }
  );

  if (page.url().includes("passkey-enrollment")) {
    await page.getByRole("button", { name: /continue without passkey/i }).click();
    await page.waitForURL((url) => !url.href.includes("passkey-enrollment"), { timeout: 5_000 });
  }
}

export async function logout(page: Page) {
  await page.goto("/auth/logout");
  await page.waitForURL((url) => !url.href.includes("/auth/logout"), { timeout: 10_000 });
}

export async function logoutStateful(page: Page) {
  await page.goto("/auth/stateful/logout");
  await page.waitForURL((url) => !url.href.includes("/auth/stateful/logout"), { timeout: 10_000 });
}

export { EMAIL };
