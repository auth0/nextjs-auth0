import { expect, test } from "@playwright/test";

/**
 * L9 — SEC-1 session_token fixation strip (browser-level, HTTP-intercept).
 *
 * Proves that a caller-supplied `session_token` on `/auth/login` never reaches
 * `/authorize`. The session token itself is never sent there: when an
 * `auth0_anon` cookie exists, the SDK exchanges the session token from that
 * cookie for a short-lived transfer ticket and sends it as `anon_transfer_token`.
 *
 * The defense has three parts:
 *   1. strip  — `session_token` and `anon_transfer_token` supplied by the caller
 *               are dropped from the authorization params.
 *   2. mint   — the ticket is minted ONLY from the session token in the encrypted
 *               `auth0_anon` cookie.
 *   3. bind   — a digest of that session token is bound to the login transaction
 *               and re-verified at the callback (`ctx.anonymousSessionLinked`).
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

    // With no cookie present, the SDK has nothing to mint a ticket from, so
    // neither parameter is sent. The strip of the attacker value while a
    // cookie-derived ticket is sent is proven by L9b.
    const url = new URL(location);
    expect(url.pathname).toBe("/authorize");
    expect(url.searchParams.get("session_token")).toBeNull();
    expect(url.searchParams.get("anon_transfer_token")).toBeNull();

    await ctx.dispose();
  });

  test("L9c — no session_token param, no cookie => none in authorize URL", async ({
    playwright,
    baseURL
  }) => {
    // Baseline: no input query param and no cookie yields neither parameter in the
    // authorize URL.
    const ctx = await playwright.request.newContext({ baseURL });
    const res = await ctx.get(`/auth/login`, { maxRedirects: 0 });

    expect(res.status()).toBe(307);
    const url = new URL(res.headers()["location"]);
    expect(url.pathname).toBe("/authorize");
    expect(url.searchParams.get("session_token")).toBeNull();
    expect(url.searchParams.get("anon_transfer_token")).toBeNull();

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

    // ...the session token is never sent to /authorize, and a ticket minted
    // from the cookie's session token IS sent (part 2). The ticket's format is
    // the authorization server's, not the SDK's, so it is not asserted.
    const url = new URL(location);
    expect(url.searchParams.get("session_token")).toBeNull();
    const ticket = url.searchParams.get("anon_transfer_token");
    expect(ticket, "cookie-derived anon_transfer_token sent").toBeTruthy();
    expect(ticket).not.toBe(ATTACKER);

    await ctx.dispose();
  });
});
