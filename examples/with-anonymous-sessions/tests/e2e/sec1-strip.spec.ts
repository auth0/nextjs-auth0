import { expect, test } from "@playwright/test";

/**
 * L9 — SEC-1 session_token fixation strip (browser-level, HTTP-intercept).
 *
 * Proves that a caller-supplied `session_token` on `/auth/login` never reaches
 * `/authorize`; only the SDK's own encrypted-cookie-derived token does. This is
 * the end-to-end browser confirmation of the unit invariant in
 * src/server/anonymous-session.flow.test.ts (:451-490 and :561).
 *
 * SEC-1 is a 3-layer defense in src/server/auth-client.ts:
 *   1. strip  — `session_token` listed in INTERNAL_AUTHORIZE_PARAMS is dropped
 *               from caller-supplied authorization params before the merge.
 *   2. inject — the token is sourced ONLY from the encrypted `auth0_anon`
 *               cookie (readAnonymousCookie), AFTER the strip.
 *   3. bind   — a digest of the injected token is bound to the CSRF txn state
 *               and re-verified at callback (verifyAnonymousSessionLink).
 *
 * We intercept the 307 redirect (do NOT follow it to Auth0) and assert on the
 * Location header. Uses APIRequestContext (pure HTTP, no page, no IdP).
 */

const ATTACKER = "ATTACKER_XYZ_pwned";

// L9b needs a real `auth0_anon` cookie, which the create route only obtains via
// a live tenant call. Gate it on the presence of tenant creds; L9a/L9c are
// creds-free and always run.
const hasCreds =
  !!process.env.AUTH0_DOMAIN &&
  !!process.env.AUTH0_CLIENT_SECRET &&
  !!process.env.AUTH0_CLIENT_ID;

test.describe("L9 — SEC-1 session_token strip", () => {
  test("L9a — attacker session_token with NO anon cookie yields no session_token in authorize URL", async ({
    playwright,
    baseURL
  }) => {
    const ctx = await playwright.request.newContext({ baseURL });
    const res = await ctx.get(
      `/auth/login?returnTo=/demo&session_token=${ATTACKER}`,
      { maxRedirects: 0 }
    );

    expect(res.status()).toBe(307);
    const location = res.headers()["location"];
    expect(location, "Location header present").toBeTruthy();

    // Attacker value must not appear anywhere in the outbound authorize URL.
    expect(location).not.toContain(ATTACKER);

    // With no cookie present, the SDK has no legitimate token to inject, so the
    // absence of any session_token proves non-injection. The strip of the
    // attacker value (while a cookie-derived token survives) is proven by L9b.
    const url = new URL(location);
    expect(url.pathname).toBe("/authorize");
    expect(url.searchParams.get("session_token")).toBeNull();

    await ctx.dispose();
  });

  test("L9c — no session_token param, no cookie => none in authorize URL", async ({
    playwright,
    baseURL
  }) => {
    // Baseline: no input query param and no cookie yields no session_token in the
    // authorize URL. Parity with unit flow.test.ts:561.
    const ctx = await playwright.request.newContext({ baseURL });
    const res = await ctx.get(`/auth/login`, { maxRedirects: 0 });

    expect(res.status()).toBe(307);
    const url = new URL(res.headers()["location"]);
    expect(url.pathname).toBe("/authorize");
    expect(url.searchParams.get("session_token")).toBeNull();

    await ctx.dispose();
  });

  test("L9b — attacker token WITH legit anon cookie: only cookie-derived token survives", async ({
    playwright,
    baseURL
  }) => {
    test.skip(
      !hasCreds,
      "needs live tenant creds to mint a real auth0_anon cookie"
    );

    // Single context retains the Set-Cookie from create across the login call.
    const ctx = await playwright.request.newContext({ baseURL });

    const create = await ctx.post(`/api/anon/create`, {
      data: { metadata: { cart_id: "sec1_test" } },
      headers: { "Content-Type": "application/json" }
    });

    // The POST /api/anon/create hits a LIVE tenant. If the tenant is unreachable
    // or creds are stale, skip rather than fail red.
    if (create.status() !== 201) {
      await ctx.dispose();
      test.skip(
        true,
        `L9b needs a live-reachable tenant to mint auth0_anon; create returned ${create.status()}`
      );
    }

    const res = await ctx.get(
      `/auth/login?returnTo=/demo&session_token=${ATTACKER}`,
      { maxRedirects: 0 }
    );
    expect(res.status()).toBe(307);
    const location = res.headers()["location"];

    // Attacker value never survives...
    expect(location).not.toContain(ATTACKER);

    // ...but a legit cookie-derived token IS injected (layer 2), and it is not
    // the attacker value. These two are the security-meaningful invariants:
    // caller input is dropped and replaced by the SDK's own cookie-sourced
    // token. We deliberately do NOT assert the token's internal format: the
    // value is minted by the authorization server (observed to carry an
    // "ANONYMOUS_SESSION_" prefix on this tenant), not by the SDK, so its shape
    // is not a stable contract to pin a test to.
    const injected = new URL(location).searchParams.get("session_token");
    expect(injected, "cookie-derived session_token injected").toBeTruthy();
    expect(injected).not.toBe(ATTACKER);

    await ctx.dispose();
  });
});
