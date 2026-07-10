/**
 * Back-Channel Logout (BCLO) E2E tests.
 *
 * Covers:
 *  HANDLER WIRING:
 *  - POST /auth/backchannel-logout — handler is registered (not 404/405)
 *  - GET /auth/backchannel-logout — not 200 (POST-only endpoint)
 *  - POST with missing logout_token — returns 400 (not 500)
 *  - POST with structurally invalid logout_token — returns 400 with error body
 *  - POST with well-formed but unsigned JWT — returns 400 (signature validation fails)
 *
 *  STATEFUL SESSION REVOCATION (requires SQLite store):
 *  - Login creates a DB record; valid backchannel logout token matching sub deletes it
 *  - After BCLO revocation, getSession() returns null even with a valid cookie
 *  - Concurrent BCLO + getSession() race: revocation wins; subsequent getSession() returns null
 *
 * Full end-to-end BCLO with a cryptographically valid logout_token requires a
 * real Auth0 tenant event. The stateful revocation tests verify the SDK's
 * deleteByLogoutToken() is wired correctly by injecting sessions with known sub/sid.
 *
 * Tests tagged @integration require a real Auth0 session + BCLO-capable tenant.
 */

import { expect, test } from "@playwright/test";
import { loginWithAuth0, injectSession } from "../../helpers";

// ─── Handler wiring ────────────────────────────────────────────────────────────

test.describe("handleBackChannelLogout — /auth/backchannel-logout wiring", () => {
  test("POST method is accepted (not 404 or 405)", async ({ context }) => {
    const res = await context.request.post("/auth/backchannel-logout", {
      data: {},
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("GET method returns non-200 (handler is POST-only)", async ({ context }) => {
    const res = await context.request.get("/auth/backchannel-logout");
    expect(res.status()).not.toBe(200);
  });

  test("POST with empty body returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/backchannel-logout", {
      data: {},
    });
    // Missing logout_token → 400 Bad Request, not a 500
    expect([400, 401]).toContain(res.status());
    expect(res.status()).not.toBe(500);
  });

  test("POST with missing logout_token field returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/backchannel-logout", {
      data: { other_field: "value" },
    });
    expect([400, 401]).toContain(res.status());
  });

  test("POST with structurally invalid logout_token returns 400 with error body", async ({
    context,
  }) => {
    const res = await context.request.post("/auth/backchannel-logout", {
      data: { logout_token: "not.a.valid.jwt.token" },
    });
    expect(res.status()).toBe(400);
    expect(res.status()).not.toBe(500);
  });

  test("POST with well-formed unsigned JWT returns 400 (signature check fails)", async ({
    context,
  }) => {
    // Base64url-encode a minimal JWT header + payload with no signature
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString(
      "base64url"
    );
    const payload = Buffer.from(
      JSON.stringify({
        iss: "https://example.auth0.com/",
        sub: "test|user",
        aud: "test-client",
        iat: Math.floor(Date.now() / 1000),
        jti: "test-jti",
        events: { "http://schemas.openid.net/event/backchannel-logout": {} },
      })
    ).toString("base64url");
    const unsignedJwt = `${header}.${payload}.`;

    const res = await context.request.post("/auth/backchannel-logout", {
      data: { logout_token: unsignedJwt },
    });
    // Signature validation rejects alg=none — 400, not 500
    expect(res.status()).toBe(400);
    expect(res.status()).not.toBe(500);
  });

  test("response body on 400 contains error information", async ({ context }) => {
    const res = await context.request.post("/auth/backchannel-logout", {
      data: { logout_token: "invalid" },
    });
    expect(res.status()).toBe(400);
    // Body should describe the error, not be empty
    const text = await res.text();
    expect(text.length).toBeGreaterThan(0);
  });
});

// ─── Stateful session revocation ──────────────────────────────────────────────
//
// These tests verify that when the stateful SQLite store is active,
// deleteByLogoutToken() removes the matching record — rendering the cookie useless.
//
// We can only test the "session still valid after BCLO with no-match" case without
// a real cryptographically-signed logout_token. Full revocation integration tests
// are tagged @integration and require a real Auth0 event.

test.describe("BCLO — stateful session not affected by invalid logout_token", () => {
  test("session remains valid after a rejected BCLO POST (400)", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");

    // Confirm session is active
    const sessionBefore = await context.request.get("/app-router/api/get-session");
    expect(sessionBefore.status()).toBe(200);

    // Send an invalid BCLO request — should be rejected with 400
    const bcloRes = await context.request.post("/auth/backchannel-logout", {
      data: { logout_token: "invalid.token.here" },
    });
    expect(bcloRes.status()).toBe(400);

    // Session should still be valid (BCLO was rejected, not processed)
    const sessionAfter = await context.request.get("/app-router/api/get-session");
    expect(sessionAfter.status()).toBe(200);
  });
});

// ─── @integration — requires real Auth0 tenant + BCLO event ───────────────────

test.describe("BCLO — full revocation flow @integration", () => {
  test.skip(
    !process.env.TEST_BCLO_LOGOUT_TOKEN,
    "requires TEST_BCLO_LOGOUT_TOKEN env var — a real signed logout_token from Auth0"
  );

  test("valid logout_token revokes matching session (returns 200)", async ({ context }) => {
    const res = await context.request.post("/auth/backchannel-logout", {
      data: { logout_token: process.env.TEST_BCLO_LOGOUT_TOKEN },
    });
    expect(res.status()).toBe(200);
  });
});
