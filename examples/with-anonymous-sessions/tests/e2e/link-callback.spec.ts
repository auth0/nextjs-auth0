import { expect, test } from "@playwright/test";

/**
 * L10 — anonymous -> login -> callback link (real login, GATED).
 *
 * Proves that when an `auth0_anon` cookie exists at login, completing a real
 * Universal Login round-trip results in `ctx.anonymousSessionLinked === true`
 * at the callback. The example's onCallback (lib/auth0.ts) surfaces that by
 * appending `?linked=true` to the returnTo redirect; LoginToLinkButton renders
 * the green success banner off that query param.
 *
 * GATED: needs a real tenant test user. Set TEST_USER_EMAIL + TEST_USER_PASSWORD and
 * a complete .env.local (dev-ozu). Skips otherwise, so CI never runs it.
 *
 * Run recipe:
 *   TEST_USER_EMAIL=you@example.com TEST_USER_PASSWORD=... \
 *     pnpm exec playwright test link-callback
 */

const TEST_USER_EMAIL = process.env.TEST_USER_EMAIL;
const TEST_USER_PASSWORD = process.env.TEST_USER_PASSWORD;
const gated = !TEST_USER_EMAIL || !TEST_USER_PASSWORD;

test.describe("L10 — anon -> login -> callback link", () => {
  test.skip(
    gated,
    "needs TEST_USER_EMAIL + TEST_USER_PASSWORD for a real login"
  );

  test("L10a — completing login with an anon cookie links the session", async ({
    page,
    context
  }) => {
    // 1. Establish an anonymous session (sets auth0_anon cookie).
    await page.goto("/");
    // The create route is the reliable way to mint the cookie in a test; the
    // "Enter as Guest" link hits GET /auth/anonymous-session which only READS.
    const create = await context.request.post("/api/anon/create", {
      data: { metadata: { cart_id: "l10_link" } },
      headers: { "Content-Type": "application/json" }
    });
    expect(create.status()).toBe(201);

    const cookies = await context.cookies();
    expect(
      cookies.some((c) => c.name.startsWith("auth0_anon")),
      "auth0_anon cookie present before login"
    ).toBe(true);

    // 2. Go to the demo page and start the link login.
    await page.goto("/demo");
    await page.getByRole("button", { name: "Login to Link" }).click();

    // 3. Real Auth0 Universal Login (identifier-first: username step, then a
    //    separate password step).
    await page.waitForURL(/\/authorize|\/u\/login|\.auth0\.com/, {
      timeout: 15_000
    });

    // The submit button is the VISIBLE "Continue" (exact name avoids the social
    // "Continue with ..." buttons and the aria-hidden decoy submit that
    // otherwise intercepts pointer events).
    const submit = page.getByRole("button", { name: "Continue", exact: true });

    const username = page.locator(
      'input[name="username"], input[id="username"]'
    );
    await username.waitFor({ state: "visible", timeout: 15_000 });
    await username.fill(TEST_USER_EMAIL!);

    const password = page.locator(
      'input[name="password"], input[id="password"]'
    );
    if (await password.isVisible().catch(() => false)) {
      // Single-page form: username + password shown together.
      await password.fill(TEST_USER_PASSWORD!);
      await submit.click();
    } else {
      // Identifier-first: submit username, then fill password on the next page.
      await submit.click();
      await password.waitFor({ state: "visible", timeout: 15_000 });
      await password.fill(TEST_USER_PASSWORD!);
      await submit.click();
    }

    // Optional consent screen on first run. If the button is present we require
    // the click to succeed (no silent catch) so a broken consent step surfaces
    // as a clear failure rather than a downstream URL timeout.
    const consent = page.locator(
      'button[value="accept"], button:has-text("Accept")'
    );
    if ((await consent.count()) > 0) {
      await consent.first().click();
    }

    // 4. Land back on /demo?linked=true after the callback.
    //
    // The example's onCallback (lib/auth0.ts) appends `?linked=true` when
    // ctx.anonymousSessionLinked === true AND a session exists (lib/auth0.ts:34).
    // The query param and banner below are the observable proxy for that
    // server-side flag in this demo. A deeper assertion on the raw flag would
    // need a dedicated debug endpoint; out of scope for the demo.
    await page.waitForURL(/\/demo(\?.*)?$/, { timeout: 20_000 });
    expect(page.url()).toContain("linked=true");

    // 5. The green success banner renders off the linked flag.
    await expect(
      page.getByText("Anonymous session successfully linked")
    ).toBeVisible();
  });
});
