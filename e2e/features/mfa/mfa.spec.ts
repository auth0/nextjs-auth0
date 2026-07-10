/**
 * MFA E2E tests.
 *
 * Covers:
 *  SERVER (auth0.mfa.*) — called via dedicated API routes:
 *  - auth0.mfa.getAuthenticators() — 401 without session; well-formed error with bad mfaToken
 *  - auth0.mfa.challenge() — 401 without session; SDK error with invalid mfaToken
 *  - auth0.mfa.enroll() — 401 without session; SDK error with invalid mfaToken
 *  - auth0.mfa.verify() — 401 without session; SDK error with invalid mfaToken
 *
 *  MIDDLEWARE ROUTES — called via /auth/mfa/* built-in handlers:
 *  - GET /auth/mfa/authenticators — reachable, not 404/405
 *  - POST /auth/mfa/challenge — reachable, not 404/405
 *  - POST /auth/mfa/verify — reachable, not 404/405
 *  - POST /auth/mfa/associate — reachable, not 404/405
 *
 *  CLIENT (mfa singleton) — exercised via the /app-router/mfa page:
 *  - mfa.challengeWithPopup() — triggers popup flow (PopupBlockedError in headless)
 *  - GET /auth/mfa/authenticators via client fetch — route response
 *  - POST /auth/mfa/challenge via client fetch — route response
 *
 * Full end-to-end MFA completion requires a tenant with MFA enabled + registered factor.
 * These tests lock down the SDK's HTTP surface and method wiring.
 */

import { expect, test } from "@playwright/test";
import { loginWithAuth0 } from "../../helpers";

const FAKE_MFA_TOKEN = "fake.encrypted.mfa_token";

// ─── Server auth0.mfa.getAuthenticators() ────────────────────────────────────

test.describe("auth0.mfa.getAuthenticators() — server method", () => {
  test("returns 401 without session", async ({ context }) => {
    const res = await context.request.post("/app-router/api/mfa/get-authenticators", {
      data: { mfaToken: FAKE_MFA_TOKEN },
    });
    expect(res.status()).toBe(401);
  });

  test("returns 400 with well-formed error when mfaToken is missing", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/mfa/get-authenticators", {
      data: {},
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("returns SDK error (not 500) for invalid mfaToken when authenticated", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/mfa/get-authenticators", {
      data: { mfaToken: FAKE_MFA_TOKEN },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

// ─── Server auth0.mfa.challenge() ────────────────────────────────────────────

test.describe("auth0.mfa.challenge() — server method", () => {
  test("returns 401 without session", async ({ context }) => {
    const res = await context.request.post("/app-router/api/mfa/challenge", {
      data: { mfaToken: FAKE_MFA_TOKEN, challengeType: "otp" },
    });
    expect(res.status()).toBe(401);
  });

  test("returns SDK error (not 500) for invalid mfaToken when authenticated", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/mfa/challenge", {
      data: { mfaToken: FAKE_MFA_TOKEN, challengeType: "otp" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

// ─── Server auth0.mfa.enroll() ───────────────────────────────────────────────

test.describe("auth0.mfa.enroll() — server method", () => {
  test("returns 401 without session", async ({ context }) => {
    const res = await context.request.post("/app-router/api/mfa/enroll", {
      data: { mfaToken: FAKE_MFA_TOKEN, authenticatorTypes: ["otp"] },
    });
    expect(res.status()).toBe(401);
  });

  test("returns SDK error (not 500) for invalid mfaToken when authenticated", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/mfa/enroll", {
      data: { mfaToken: FAKE_MFA_TOKEN, authenticatorTypes: ["otp"] },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

// ─── Server auth0.mfa.verify() ───────────────────────────────────────────────

test.describe("auth0.mfa.verify() — server method", () => {
  test("returns 401 without session", async ({ context }) => {
    const res = await context.request.post("/app-router/api/mfa/verify", {
      data: { mfaToken: FAKE_MFA_TOKEN, otp: "123456" },
    });
    expect(res.status()).toBe(401);
  });

  test("returns SDK error (not 500) for invalid mfaToken when authenticated", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/mfa/verify", {
      data: { mfaToken: FAKE_MFA_TOKEN, otp: "123456" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

// ─── Middleware /auth/mfa/* route handlers — param validation ────────────────

test.describe("handleGetAuthenticators — GET /auth/mfa/authenticators", () => {
  test("route is registered (not 404)", async ({ context }) => {
    const res = await context.request.get("/auth/mfa/authenticators");
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing Authorization header returns 400 with error", async ({ context }) => {
    // extractMfaToken requires Authorization: Bearer <token>
    const res = await context.request.get("/auth/mfa/authenticators");
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("malformed mfa_token returns structured error (not 500)", async ({ context }) => {
    const res = await context.request.get("/auth/mfa/authenticators", {
      headers: { Authorization: "Bearer not-a-valid-encrypted-token" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

test.describe("handleChallenge — POST /auth/mfa/challenge", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/challenge", {
      data: { challenge_type: "otp" },
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing mfa_token in body returns 400", async ({ context }) => {
    // handleChallenge reads mfa_token from body (not header)
    const res = await context.request.post("/auth/mfa/challenge", {
      data: { challenge_type: "otp" },
    });
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("missing challenge_type returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/challenge", {
      data: { mfa_token: FAKE_MFA_TOKEN },
    });
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("optional authenticator_id is accepted without error change", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/challenge", {
      data: { mfa_token: FAKE_MFA_TOKEN, challenge_type: "otp", authenticator_id: "auth|123" },
    });
    // Still fails (bad token) but not 500 — authenticator_id path was reached
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

test.describe("handleVerify — POST /auth/mfa/verify", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/verify", { data: { otp: "000000" } });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing Authorization header returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/verify", {
      data: { otp: "000000" },
    });
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("otp credential path — returns structured error (not 500)", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/verify", {
      headers: { Authorization: `Bearer ${FAKE_MFA_TOKEN}` },
      data: { otp: "000000" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("oob_code + binding_code credential path — returns structured error (not 500)", async ({
    context,
  }) => {
    const res = await context.request.post("/auth/mfa/verify", {
      headers: { Authorization: `Bearer ${FAKE_MFA_TOKEN}` },
      data: { oob_code: "fake-oob", binding_code: "000000" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("recovery_code credential path — returns structured error (not 500)", async ({
    context,
  }) => {
    const res = await context.request.post("/auth/mfa/verify", {
      headers: { Authorization: `Bearer ${FAKE_MFA_TOKEN}` },
      data: { recovery_code: "AAAA-BBBB-CCCC" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("no credential fields returns 400 (validateVerificationCredentialAndThrow)", async ({
    context,
  }) => {
    const res = await context.request.post("/auth/mfa/verify", {
      headers: { Authorization: `Bearer ${FAKE_MFA_TOKEN}` },
      data: {},
    });
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

test.describe("handleAssociate — POST /auth/mfa/associate", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/associate", {
      data: { authenticator_types: ["otp"] },
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing Authorization header returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/associate", {
      data: { authenticator_types: ["otp"] },
    });
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("missing authenticator_types returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/associate", {
      headers: { Authorization: `Bearer ${FAKE_MFA_TOKEN}` },
      data: {},
    });
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("otp authenticator type — returns structured error (not 500)", async ({ context }) => {
    const res = await context.request.post("/auth/mfa/associate", {
      headers: { Authorization: `Bearer ${FAKE_MFA_TOKEN}` },
      data: { authenticator_types: ["otp"] },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("oob authenticator with oob_channels=[email] — returns structured error (not 500)", async ({
    context,
  }) => {
    const res = await context.request.post("/auth/mfa/associate", {
      headers: { Authorization: `Bearer ${FAKE_MFA_TOKEN}` },
      data: { authenticator_types: ["oob"], oob_channels: ["email"], email: "test@example.com" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("oob authenticator with oob_channels=[sms] and phone_number — returns structured error (not 500)", async ({
    context,
  }) => {
    const res = await context.request.post("/auth/mfa/associate", {
      headers: { Authorization: `Bearer ${FAKE_MFA_TOKEN}` },
      data: {
        authenticator_types: ["oob"],
        oob_channels: ["sms"],
        phone_number: "+15550000000",
      },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

// ─── Client mfa singleton — via /app-router/mfa page ─────────────────────────

test.describe("Client mfa singleton — page buttons", () => {
  test("page renders controls when authenticated", async ({ page }) => {
    await loginWithAuth0(page, "/app-router/mfa");
    await expect(page.locator("#challenge-with-popup")).toBeVisible();
    await expect(page.locator("#get-authenticators-route")).toBeVisible();
    await expect(page.locator("#mfa-challenge-route")).toBeVisible();
    await expect(page.locator("#mfa-get-authenticators")).toBeVisible();
    await expect(page.locator("#mfa-enroll")).toBeVisible();
    await expect(page.locator("#mfa-verify")).toBeVisible();
  });

  test("GET /auth/mfa/authenticators via client fetch populates result or error", async ({
    page,
  }) => {
    await loginWithAuth0(page, "/app-router/mfa");
    await page.locator("#get-authenticators-route").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
  });

  test("POST /auth/mfa/challenge via client fetch populates result or error", async ({ page }) => {
    await loginWithAuth0(page, "/app-router/mfa");
    await page.locator("#mfa-challenge-route").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
  });

  test("mfa.challengeWithPopup() surfaces an error in headless (popup blocked or no audience)", async ({
    page,
  }) => {
    await loginWithAuth0(page, "/app-router/mfa");
    await page.locator("#challenge-with-popup").click();
    // In headless Playwright, popup is blocked → error is set
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 15_000 }
    );
    const error = await page.locator("#error").textContent();
    const result = await page.locator("#result").textContent();
    // Popup blocked, missing audience, or network error — either way error is set
    expect((error?.length ?? 0) + (result?.length ?? 0)).toBeGreaterThan(0);
  });

  test("mfa.getAuthenticators() client singleton surfaces result or error (not silent)", async ({
    page,
  }) => {
    await loginWithAuth0(page, "/app-router/mfa");
    await page.locator("#mfa-get-authenticators").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
    // fake mfaToken → SDK error surfaced in #error; never silent
    const error = await page.locator("#error").textContent();
    const result = await page.locator("#result").textContent();
    expect((error?.length ?? 0) + (result?.length ?? 0)).toBeGreaterThan(0);
  });

  test("mfa.enroll() client singleton surfaces result or error (not silent)", async ({
    page,
  }) => {
    await loginWithAuth0(page, "/app-router/mfa");
    await page.locator("#mfa-enroll").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
    const error = await page.locator("#error").textContent();
    const result = await page.locator("#result").textContent();
    expect((error?.length ?? 0) + (result?.length ?? 0)).toBeGreaterThan(0);
  });

  test("mfa.verify() client singleton surfaces result or error (not silent)", async ({
    page,
  }) => {
    await loginWithAuth0(page, "/app-router/mfa");
    await page.locator("#mfa-verify").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
    const error = await page.locator("#error").textContent();
    const result = await page.locator("#result").textContent();
    expect((error?.length ?? 0) + (result?.length ?? 0)).toBeGreaterThan(0);
  });
});
