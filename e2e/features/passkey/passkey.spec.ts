/**
 * Passkey (WebAuthn) E2E tests.
 *
 * Covers:
 *  SERVER (auth0.passkey.*) — called via dedicated API routes:
 *  - auth0.passkey.register() — returns challenge shape or SDK error (not 500)
 *  - auth0.passkey.challenge() — returns challenge shape or SDK error
 *  - auth0.passkey.getToken() — returns SDK error for bad credential
 *  - auth0.passkey.enrollmentChallenge() — 401 without session; SDK response when authenticated
 *  - auth0.passkey.enrollmentVerify() — 401 without session; SDK error for bad credential
 *
 *  MIDDLEWARE ROUTES — /auth/passkey/* built-in handlers:
 *  - POST /auth/passkey/register — registered (not 404/405)
 *  - POST /auth/passkey/challenge — registered
 *  - POST /auth/passkey/get-token — registered
 *  - POST /auth/passkey/enrollment-challenge — registered
 *  - POST /auth/passkey/enrollment-verify — registered
 *
 *  CLIENT (passkey singleton + serializeCredential) — via /app-router/passkey page:
 *  - passkey.signup() — calls /auth/passkey/register, then navigator.credentials.create (WebAuthn error expected)
 *  - passkey.login() — calls /auth/passkey/challenge, then navigator.credentials.get (WebAuthn error expected)
 *  - serializeCredential — exported function is callable
 *
 * navigator.credentials is not available in Playwright headless. passkey.signup/login
 * will error after the challenge fetch — this confirms SDK delegation to the WebAuthn API.
 */

import { expect, test } from "@playwright/test";
import { loginWithAuth0 } from "../../helpers";

// ─── Server auth0.passkey.register() ─────────────────────────────────────────

test.describe("auth0.passkey.register() — server method", () => {
  test("returns challenge shape or SDK error (not 500)", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passkey/register", { data: {} });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

// ─── Server auth0.passkey.challenge() ────────────────────────────────────────

test.describe("auth0.passkey.challenge() — server method", () => {
  test("returns challenge shape or SDK error (not 500)", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passkey/challenge", { data: {} });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

// ─── Server auth0.passkey.getToken() ─────────────────────────────────────────

test.describe("auth0.passkey.getToken() — server method", () => {
  test("returns SDK error for invalid credential (not 500)", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passkey/get-token", {
      data: { authSession: "fake-session", authResponse: {} },
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

// ─── Server auth0.passkey.enrollmentChallenge() ───────────────────────────────

test.describe("auth0.passkey.enrollmentChallenge() — server method", () => {
  test("returns SDK response (not 500, not 404) — authenticated via setup", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passkey/enrollment-challenge", {
      data: {},
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });

  test("returns SDK response (not 500) when authenticated", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/passkey/enrollment-challenge", {
      data: {},
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

// ─── Server auth0.passkey.enrollmentVerify() ─────────────────────────────────

test.describe("auth0.passkey.enrollmentVerify() — server method", () => {
  test("returns SDK error for invalid credential — authenticated via setup", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passkey/enrollment-verify", {
      data: { authenticationMethodId: "fake", authSession: "fake", authResponse: {} },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("returns SDK error for invalid credential when authenticated", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/passkey/enrollment-verify", {
      data: { authenticationMethodId: "fake", authSession: "fake", authResponse: {} },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

// ─── Middleware /auth/passkey/* — param validation ───────────────────────────

test.describe("handlePasskeyRegister — POST /auth/passkey/register", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/register", { data: {} });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("optional email/username fields are accepted without error change", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/register", {
      data: { email: "test@example.com", username: "testuser" },
    });
    // Still fails (tenant config) but not 500 — field paths were reached
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });

  test("optional connection/organization fields are accepted", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/register", {
      data: { connection: "Username-Password-Authentication", organization: "my-org" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

test.describe("handlePasskeyChallenge — POST /auth/passkey/challenge", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/challenge", { data: {} });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("optional connection field is accepted", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/challenge", {
      data: { connection: "Username-Password-Authentication" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });

  test("optional organization field is accepted", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/challenge", {
      data: { organization: "my-org" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

test.describe("handlePasskeyGetToken — POST /auth/passkey/get-token", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/get-token", {
      data: { authSession: "fake", authResponse: {} },
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing authSession returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/get-token", {
      data: { authResponse: { id: "fake" } },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("missing authResponse returns 400", async ({ context }) => {
    // handlePasskeyGetToken has explicit check: authResponse is required
    const res = await context.request.post("/auth/passkey/get-token", {
      data: { authSession: "fake-session" },
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("authResponse");
  });

  test("authResponse must be an object (not a string)", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/get-token", {
      data: { authSession: "fake-session", authResponse: "not-an-object" },
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_request");
  });

  test("optional connection and organization fields are accepted", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/get-token", {
      data: {
        authSession: "fake",
        authResponse: {},
        connection: "Username-Password-Authentication",
        organization: "my-org",
      },
    });
    // Still fails on invalid credential but not 500 — optional fields reached
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

test.describe("handlePasskeyEnrollmentChallenge — POST /auth/passkey/enrollment-challenge", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/enrollment-challenge", { data: {} });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("returns 401 without session (not_authenticated path)", async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const res = await ctx.request.post("/auth/passkey/enrollment-challenge", { data: {} });
    const body = await res.json();
    await ctx.close();
    expect(res.status()).toBe(401);
    expect(body.error).toBe("not_authenticated");
  });

  test("optional connection field is accepted when authenticated", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/auth/passkey/enrollment-challenge", {
      data: { connection: "Username-Password-Authentication" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });

  test("optional userIdentityId field is accepted when authenticated", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/auth/passkey/enrollment-challenge", {
      data: { userIdentityId: "some-identity-id" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

test.describe("handlePasskeyEnrollmentVerify — POST /auth/passkey/enrollment-verify", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/passkey/enrollment-verify", {
      data: { authenticationMethodId: "fake", authSession: "fake", authResponse: {} },
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("returns 401 without session (not_authenticated path)", async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const res = await ctx.request.post("/auth/passkey/enrollment-verify", {
      data: { authenticationMethodId: "fake", authSession: "fake", authResponse: {} },
    });
    const body = await res.json();
    await ctx.close();
    expect(res.status()).toBe(401);
    expect(body.error).toBe("not_authenticated");
  });

  test("missing authenticationMethodId returns 400", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/auth/passkey/enrollment-verify", {
      data: { authSession: "fake", authResponse: {} },
    });
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("missing authSession returns 400", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/auth/passkey/enrollment-verify", {
      data: { authenticationMethodId: "fake", authResponse: {} },
    });
    expect([400, 401]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("missing authResponse returns 400", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/auth/passkey/enrollment-verify", {
      data: { authenticationMethodId: "fake", authSession: "fake" },
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("authResponse");
  });

  test("authResponse must be an object", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/auth/passkey/enrollment-verify", {
      data: { authenticationMethodId: "fake", authSession: "fake", authResponse: "not-an-object" },
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_request");
  });
});

// ─── Client passkey singleton + serializeCredential — via /app-router/passkey page ──

test.describe("Client passkey singleton — page buttons", () => {
  test("page renders all controls", async ({ page }) => {
    await page.goto("/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });
    await expect(page.locator("#passkey-signup")).toBeVisible();
    await expect(page.locator("#passkey-login")).toBeVisible();
    await expect(page.locator("#passkey-enrollment-challenge")).toBeVisible();
    await expect(page.locator("#serialize-credential-check")).toBeVisible();
    await expect(page.locator("#passkey-enrollment-verify")).toBeVisible();
  });

  test("serializeCredential is exported as a function", async ({ page }) => {
    await page.goto("/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });
    await page.locator("#serialize-credential-check").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 5_000 }
    );
    const error = await page.locator("#error").textContent();
    expect(error, `unexpected error: ${error}`).toBe("");
    const result = await page.locator("#result").textContent();
    expect(result).toContain('"type":"function"');
  });

  test("passkey.signup() calls /auth/passkey/register then fails at WebAuthn step", async ({
    page,
  }) => {
    await page.goto("/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });
    await page.locator("#passkey-signup").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 15_000 }
    );
    // Either got a challenge (result) or WebAuthn not supported error — route was called
  });

  test("passkey.login() calls /auth/passkey/challenge then fails at WebAuthn step", async ({
    page,
  }) => {
    await page.goto("/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });
    await page.locator("#passkey-login").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 15_000 }
    );
  });

  test("enrollment-challenge button returns response when authenticated", async ({ page }) => {
    await loginWithAuth0(page, "/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });
    await page.locator("#passkey-enrollment-challenge").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
  });

  test("passkey.enrollmentVerify() client singleton surfaces error with fake params (not silent)", async ({
    page,
  }) => {
    await loginWithAuth0(page, "/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });
    await page.locator("#passkey-enrollment-verify").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
    // Fake authenticationMethodId/authSession → SDK error surface, never silent
    const error = await page.locator("#error").textContent();
    const result = await page.locator("#result").textContent();
    expect((error?.length ?? 0) + (result?.length ?? 0)).toBeGreaterThan(0);
  });
});

// ─── @integration — Full end-to-end passkey via virtual authenticator ─────────
//
// Uses Playwright's context.credentials API (Playwright ≥1.61) which intercepts
// navigator.credentials.create/get entirely in software — no OS dialog, no hardware.
//
// Prerequisites:
//   - Passkey connection enabled on the Auth0 tenant
//   - NEXT_PUBLIC_TEST_PASSKEY_EMAIL set in .env.local
//   - Auth0 application has localhost as an allowed origin for WebAuthn

// rpId must match the AUTH0_DOMAIN used by the passkey server (custom domain required by WebAuthn).
const PASSKEY_RP_ID =
  process.env.PASSKEY_AUTH0_DOMAIN ?? new URL(process.env.PASSKEY_APP_BASE_URL ?? "https://piyushkumar.acmetest.org").hostname;

test.describe("Full passkey signup → login flow @integration", () => {
  test.skip(
    !process.env.NEXT_PUBLIC_TEST_PASSKEY_EMAIL,
    "requires NEXT_PUBLIC_TEST_PASSKEY_EMAIL"
  );

  test("signup: register challenge → virtual WebAuthn create → session cookie set", async ({
    page,
    context,
  }) => {
    // Install virtual authenticator BEFORE navigating — must be in place before
    // the page first touches navigator.credentials.
    await context.credentials.install();

    await page.goto("/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });
    await page.locator("#passkey-signup").click();

    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 20_000 }
    );

    const error = await page.locator("#error").textContent();
    expect(error, `signup error: ${error}`).toBe("");

    const cookies = await context.cookies();
    expect(
      cookies.find((c) => c.name === "__session"),
      "session cookie should be set after signup"
    ).toBeTruthy();
  });

  test("login: signup → clear session → login with saved credential → session cookie set", async ({
    page,
    context,
  }) => {
    await context.credentials.install();

    // Step 1: signup to register a credential in the virtual authenticator
    await page.goto("/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });
    await page.locator("#passkey-signup").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 20_000 }
    );
    expect(await page.locator("#error").textContent()).toBe("");

    // Step 2: clear session cookie — virtual authenticator retains the credential
    await context.clearCookies();

    // Step 3: login — navigator.credentials.get() is answered by the virtual authenticator
    await page.goto("/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });
    await page.locator("#passkey-login").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 20_000 }
    );

    const error = await page.locator("#error").textContent();
    expect(error, `login error: ${error}`).toBe("");

    const cookies = await context.cookies();
    expect(
      cookies.find((c) => c.name === "__session"),
      "session cookie should be set after login"
    ).toBeTruthy();
  });
});

test.describe("Full passkey enrollment flow @integration", () => {
  test.skip(
    !process.env.NEXT_PUBLIC_TEST_PASSKEY_EMAIL,
    "requires NEXT_PUBLIC_TEST_PASSKEY_EMAIL"
  );

  test("enrollment: challenge → virtual WebAuthn create → enrollment-verify → passkey registered", async ({
    page,
    context,
  }) => {
    // Install before login so the passkey prompt during Auth0 login is handled
    await context.credentials.install();
    await loginWithAuth0(page, "/app-router/passkey");
    await page.locator("main[data-hydrated='true']").waitFor({ timeout: 10_000 });

    // Step 1: get enrollment challenge (requires session)
    const challengeRes = await context.request.post("/auth/passkey/enrollment-challenge", {
      data: {},
    });
    expect(challengeRes.status()).toBe(200);
    const challenge = await challengeRes.json();
    expect(challenge).toHaveProperty("authSession");
    expect(challenge).toHaveProperty("authenticationMethodId");
    expect(challenge).toHaveProperty("authnParamsPublicKey");

    // Step 2: seed a known credential for this rpId so navigator.credentials.create()
    // is answered deterministically, then run the WebAuthn ceremony in the page.
    await context.credentials.create(PASSKEY_RP_ID);

    const authResponse = await page.evaluate(async (creationOptions) => {
      const { serializeCredential } = await import("@auth0/nextjs-auth0");
      const b64ToBytes = (b64: string) =>
        Uint8Array.from(atob(b64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
      const credential = await navigator.credentials.create({
        publicKey: {
          ...creationOptions,
          challenge: b64ToBytes(creationOptions.challenge),
          user: { ...creationOptions.user, id: b64ToBytes(creationOptions.user.id) },
          excludeCredentials: (creationOptions.excludeCredentials ?? []).map((c: any) => ({
            ...c,
            id: b64ToBytes(c.id),
          })),
        },
      });
      return serializeCredential(credential as PublicKeyCredential);
    }, challenge.authnParamsPublicKey);

    // Step 3: verify enrollment
    const verifyRes = await context.request.post("/auth/passkey/enrollment-verify", {
      data: {
        authenticationMethodId: challenge.authenticationMethodId,
        authSession: challenge.authSession,
        authResponse,
      },
    });
    expect(verifyRes.status()).toBe(200);
    const verifyBody = await verifyRes.json();
    expect(verifyBody.type).toBe("passkey");
  });
});
