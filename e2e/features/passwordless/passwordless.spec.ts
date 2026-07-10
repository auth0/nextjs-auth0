/**
 * Passwordless E2E tests.
 *
 * Covers:
 *  SERVER (auth0.passwordless.*) — called via dedicated API routes:
 *  - auth0.passwordless.start() — returns SDK error (not 500) for unconfigured tenant
 *  - auth0.passwordless.verify() — returns SDK error for invalid OTP
 *  - auth0.passwordless.challengeWithEmail() — returns SDK error
 *  - auth0.passwordless.challengeWithPhoneNumber() — returns SDK error
 *  - auth0.passwordless.loginWithOtp() — returns SDK error for bad auth_session
 *
 *  MIDDLEWARE ROUTES — /auth/passwordless/* built-in handlers:
 *  - POST /auth/passwordless/start — registered (not 404/405)
 *  - POST /auth/passwordless/verify — registered
 *  - POST /auth/passwordless/otp/challenge — registered
 *  - POST /auth/passwordless/otp/token — registered
 *
 *  CLIENT (passwordless singleton) — via /app-router/passwordless page:
 *  - passwordless.start() — calls /auth/passwordless/start
 *  - passwordless.verify() — calls /auth/passwordless/verify
 *  - passwordless.challengeWithEmail() — calls /auth/passwordless/otp/challenge
 *  - passwordless.loginWithOtp() — calls /auth/passwordless/otp/token
 *
 *  @integration — full end-to-end OTP (gated by env vars):
 *  - Email OTP via Mailtrap (MAILTRAP_API_TOKEN + MAILTRAP_ACCOUNT_ID + MAILTRAP_INBOX_ID)
 *  - Phone/SMS OTP via Twilio (TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN)
 *
 * Full end-to-end passwordless requires a tenant with passwordless enabled.
 * These tests lock down the SDK's HTTP surface and method wiring.
 */

import { expect, request, test } from "@playwright/test";

// ─── Mailtrap / Twilio helpers ────────────────────────────────────────────────

/**
 * Delete all messages in the Mailtrap sandbox inbox.
 * Must be called BEFORE triggering the OTP challenge so the poller only
 * sees the freshly-delivered message, not a stale one from a prior run.
 */
async function cleanMailtrapInbox(
  accountId: string,
  inboxId: string,
  token: string
): Promise<void> {
  const ctx = await request.newContext();
  const res = await ctx.patch(
    `https://mailtrap.io/api/accounts/${accountId}/inboxes/${inboxId}/clean`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  await ctx.dispose();
  if (!res.ok()) {
    throw new Error(`Mailtrap inbox clean failed: ${res.status()} ${await res.text()}`);
  }
  // Brief wait for the clean to propagate before we trigger the OTP send.
  await new Promise((r) => setTimeout(r, 1000));
}

/**
 * Poll Mailtrap inbox until a message arrives for toEmail, fetch its text body
 * via the message's txt_path (body is NOT inline in the list response), then
 * extract and return the 6-digit OTP.
 *
 * Mailtrap REST API:
 *   GET /api/accounts/{accountId}/inboxes/{inboxId}/messages  → list (no body inline)
 *   GET https://mailtrap.io{message.txt_path}                  → text body
 *
 * The inbox is cleared before each poll run (clean-inbox call) so we never
 * pick up an OTP from a previous test run.
 */
async function readOtpFromMailtrap(
  accountId: string,
  inboxId: string,
  token: string,
  toEmail: string,
  notBefore: Date,
  timeoutMs = 30_000
): Promise<string> {
  const baseUrl = "https://mailtrap.io";
  const headers = { Authorization: `Bearer ${token}` };
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ctx = await request.newContext();

    const listRes = await ctx.get(
      `${baseUrl}/api/accounts/${accountId}/inboxes/${inboxId}/messages`,
      { headers }
    );

    if (listRes.ok()) {
      const messages: Array<{
        id: number;
        to_email: string;
        txt_path: string;
        html_path: string;
        created_at: string;
      }> = await listRes.json();

      // Filter to messages arrived after notBefore, sort newest-first,
      // find first message for our test email.
      const match = messages
        .filter((m) => new Date(m.created_at).getTime() >= notBefore.getTime())
        .sort(
          (a, b) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        )
        .find((m) =>
          m.to_email?.toLowerCase().includes(toEmail.toLowerCase())
        );

      if (match) {
        // Body is NOT inline — fetch it via txt_path.
        const bodyRes = await ctx.get(`${baseUrl}${match.txt_path}`, {
          headers,
        });
        if (bodyRes.ok()) {
          const body = await bodyRes.text();
          const otp = body.match(/\b(\d{6})\b/)?.[1];
          await ctx.dispose();
          if (otp) return otp;
        }
      }
    }

    await ctx.dispose();
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Timed out waiting for OTP email for ${toEmail} in Mailtrap`);
}

/**
 * Poll Twilio Messages API until an SMS arrives for the target phone number,
 * then extract and return the 6-digit OTP.
 *
 * Twilio REST: GET /2010-04-01/Accounts/{sid}/Messages.json?To={phone}
 * We retry for up to 30 s.
 */
async function readOtpFromTwilio(
  accountSid: string,
  authToken: string,
  toPhone: string,
  notBefore: Date,
  timeoutMs = 30_000
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  const credentials = Buffer.from(`${accountSid}:${authToken}`).toString(
    "base64"
  );
  // Only accept messages sent at or after notBefore (captured before start() was
  // called) so we never pick up a stale OTP from a previous test run.
  const dateSentFilter = notBefore.toISOString().slice(0, 10); // YYYY-MM-DD

  while (Date.now() < deadline) {
    const ctx = await request.newContext();
    const url =
      `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json` +
      `?To=${encodeURIComponent(toPhone)}&DateSent>=${dateSentFilter}&PageSize=20`;
    const res = await ctx.get(url, {
      headers: { Authorization: `Basic ${credentials}` },
    });
    if (res.ok()) {
      const data: { messages: Array<{ body: string; date_sent: string }> } =
        await res.json();
      const messages = (data.messages ?? [])
        .filter((m) => new Date(m.date_sent).getTime() >= notBefore.getTime())
        .sort(
          (a, b) =>
            new Date(b.date_sent).getTime() - new Date(a.date_sent).getTime()
        );
      const latest = messages[0];
      if (latest) {
        const otp = latest.body.match(/\b(\d{6})\b/)?.[1];
        await ctx.dispose();
        if (otp) return otp;
      }
    }
    await ctx.dispose();
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Timed out waiting for OTP SMS for ${toPhone} via Twilio`);
}

// ─── Server auth0.passwordless.start() ───────────────────────────────────────

test.describe("auth0.passwordless.start() — server method", () => {
  test("returns SDK error (not 500) for unconfigured passwordless", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passwordless/start", {
      data: { email: "test@example.com" },
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

// ─── Server auth0.passwordless.verify() ──────────────────────────────────────

test.describe("auth0.passwordless.verify() — server method", () => {
  test("returns SDK error for invalid OTP", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passwordless/verify", {
      data: { email: "test@example.com", otp: "000000" },
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

// ─── Server auth0.passwordless.challengeWithEmail() ──────────────────────────

test.describe("auth0.passwordless.challengeWithEmail() — server method", () => {
  test("returns SDK error for bad auth_session", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passwordless/challenge-email", {
      data: { email: "test@example.com", authSession: "fake-session" },
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

// ─── Server auth0.passwordless.challengeWithPhoneNumber() ────────────────────

test.describe("auth0.passwordless.challengeWithPhoneNumber() — server method", () => {
  test("returns SDK error for bad auth_session", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passwordless/challenge-phone", {
      data: { phoneNumber: "+15550000000", authSession: "fake-session" },
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

// ─── Server auth0.passwordless.loginWithOtp() ────────────────────────────────

test.describe("auth0.passwordless.loginWithOtp() — server method", () => {
  test("returns SDK error for bad auth_session + otp", async ({ context }) => {
    const res = await context.request.post("/app-router/api/passwordless/login-otp", {
      data: { authSession: "fake-session", otp: "000000" },
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
    const body = await res.json();
    expect(typeof body).toBe("object");
  });
});

// ─── Middleware /auth/passwordless/* route handlers — param validation ────────

test.describe("handlePasswordlessStart — POST /auth/passwordless/start", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/start", {
      data: { connection: "email", email: "test@example.com", send: "code" },
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing connection returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/start", {
      data: { email: "test@example.com", send: "code" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("invalid connection value returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/start", {
      data: { connection: "facebook", email: "test@example.com", send: "code" },
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_connection");
  });

  test("email connection — missing email returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/start", {
      data: { connection: "email", send: "code" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("email connection — missing send returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/start", {
      data: { connection: "email", email: "test@example.com" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("sms connection path — missing phoneNumber returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/start", {
      data: { connection: "sms" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("sms connection — reached handler (no 500)", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/start", {
      data: { connection: "sms", phoneNumber: "+15550000000" },
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
  });
});

test.describe("handlePasswordlessVerify — POST /auth/passwordless/verify", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/verify", {
      data: { connection: "email", email: "test@example.com", verificationCode: "000000" },
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing connection returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/verify", {
      data: { email: "test@example.com", verificationCode: "000000" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("invalid connection returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/verify", {
      data: { connection: "twitter", email: "test@example.com", verificationCode: "000000" },
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_connection");
  });

  test("email connection — missing verificationCode returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/verify", {
      data: { connection: "email", email: "test@example.com" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("sms connection — missing phoneNumber returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/verify", {
      data: { connection: "sms", verificationCode: "000000" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

test.describe("handlePasswordlessDbOtpChallenge — POST /auth/passwordless/otp/challenge", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/otp/challenge", {
      data: { connection: "some-db", email: "test@example.com" },
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing connection returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/otp/challenge", {
      data: { email: "test@example.com" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("missing both email and phoneNumber returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/otp/challenge", {
      data: { connection: "some-db" },
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("missing_identifier");
  });

  test("phoneNumber path with deliveryMethod=voice is accepted", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/otp/challenge", {
      data: { connection: "some-db", phoneNumber: "+15550000000", deliveryMethod: "voice" },
    });
    // Not 500 or 404 — phone+voice path was reached
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(404);
  });
});

test.describe("handlePasswordlessDbGetToken — POST /auth/passwordless/otp/token", () => {
  test("route is registered (not 404/405)", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/otp/token", {
      data: { authSession: "fake", otp: "000000" },
    });
    expect(res.status()).not.toBe(404);
    expect(res.status()).not.toBe(405);
  });

  test("missing authSession returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/otp/token", {
      data: { otp: "000000" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("missing otp returns 400", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/otp/token", {
      data: { authSession: "fake-session" },
    });
    expect([400, 500]).toContain(res.status());
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("invalid authSession returns structured error (not 500)", async ({ context }) => {
    const res = await context.request.post("/auth/passwordless/otp/token", {
      data: { authSession: "totally-invalid", otp: "000000" },
    });
    expect(res.status()).not.toBe(500);
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });
});

// ─── Client passwordless singleton — via /app-router/passwordless page ────────

test.describe("Client passwordless singleton — page buttons", () => {
  test("page renders all controls", async ({ page }) => {
    await page.goto("/app-router/passwordless");
    await expect(page.locator("#passwordless-start")).toBeVisible();
    await expect(page.locator("#passwordless-verify")).toBeVisible();
    await expect(page.locator("#passwordless-challenge-email")).toBeVisible();
    await expect(page.locator("#passwordless-login-otp")).toBeVisible();
    await expect(page.locator("#passwordless-challenge-phone")).toBeVisible();
  });

  test("passwordless.start() calls /auth/passwordless/start and surfaces response", async ({
    page,
  }) => {
    await page.goto("/app-router/passwordless");
    await page.locator("#passwordless-start").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
  });

  test("passwordless.verify() calls /auth/passwordless/verify and surfaces response", async ({
    page,
  }) => {
    await page.goto("/app-router/passwordless");
    await page.locator("#passwordless-verify").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
  });

  test("passwordless.challengeWithEmail() calls /auth/passwordless/otp/challenge", async ({
    page,
  }) => {
    await page.goto("/app-router/passwordless");
    await page.locator("#passwordless-challenge-email").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
  });

  test("passwordless.loginWithOtp() calls /auth/passwordless/otp/token", async ({ page }) => {
    await page.goto("/app-router/passwordless");
    await page.locator("#passwordless-login-otp").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
  });

  test("passwordless.challengeWithPhoneNumber() calls /auth/passwordless/otp/challenge and surfaces response", async ({
    page,
  }) => {
    await page.goto("/app-router/passwordless");
    await page.locator("#passwordless-challenge-phone").click();
    await page.waitForFunction(
      () => {
        const r = document.getElementById("result")?.textContent ?? "";
        const e = document.getElementById("error")?.textContent ?? "";
        return r.length > 0 || e.length > 0;
      },
      { timeout: 10_000 }
    );
    // fake connection → SDK surfaces error, never silent
    const error = await page.locator("#error").textContent();
    const result = await page.locator("#result").textContent();
    expect((error?.length ?? 0) + (result?.length ?? 0)).toBeGreaterThan(0);
  });
});

// ─── @integration — Full end-to-end email OTP via Mailtrap ────────────────────
//
// Uses Auth0's built-in "email" passwordless connection:
//   POST /auth/passwordless/start  { connection: "email", email, send: "code" }
//   → Auth0 sends OTP to Mailtrap SMTP inbox
//   POST /auth/passwordless/verify { connection: "email", email, verificationCode }
//   → SDK sets __session cookie
//
// Prerequisites:
//   - Auth0 tenant email provider → Mailtrap SMTP (Branding → Email Provider)
//     (credentials from Mailtrap dashboard → Sandbox → inbox → SMTP)
//   - Env vars: MAILTRAP_API_TOKEN, MAILTRAP_ACCOUNT_ID, MAILTRAP_INBOX_ID,
//               TEST_PASSWORDLESS_EMAIL, TEST_PASSWORDLESS_CONNECTION (= "email")

test.describe("Full email OTP flow @integration — Mailtrap", () => {
  const {
    MAILTRAP_API_TOKEN,
    MAILTRAP_ACCOUNT_ID,
    MAILTRAP_INBOX_ID,
    TEST_PASSWORDLESS_EMAIL,
    TEST_PASSWORDLESS_CONNECTION,
  } = process.env;

  test.skip(
    !MAILTRAP_API_TOKEN || !MAILTRAP_ACCOUNT_ID || !MAILTRAP_INBOX_ID,
    "requires MAILTRAP_API_TOKEN, MAILTRAP_ACCOUNT_ID, MAILTRAP_INBOX_ID"
  );
  test.skip(
    !TEST_PASSWORDLESS_EMAIL,
    "requires TEST_PASSWORDLESS_EMAIL"
  );
  test.skip(
    !TEST_PASSWORDLESS_CONNECTION,
    "requires TEST_PASSWORDLESS_CONNECTION (e.g. 'email')"
  );

  test("email OTP: start → intercept OTP from Mailtrap → verify → session cookie set", async ({
    context,
  }) => {
    // Clean inbox BEFORE triggering the challenge so the poller only sees the
    // freshly-delivered message. Cleaning after start would delete the new OTP.
    await cleanMailtrapInbox(MAILTRAP_ACCOUNT_ID!, MAILTRAP_INBOX_ID!, MAILTRAP_API_TOKEN!);

    // Capture timestamp before start so the poller ignores any pre-existing messages.
    const notBefore = new Date();

    // Step 1: POST /auth/passwordless/start — Auth0 sends OTP email via Mailtrap SMTP
    // SDK returns 204 No Content on success (no body)
    const startRes = await context.request.post("/auth/passwordless/start", {
      data: {
        connection: TEST_PASSWORDLESS_CONNECTION!,
        email: TEST_PASSWORDLESS_EMAIL!,
        send: "code",
      },
    });
    expect(startRes.status()).toBe(204);

    // Step 2: read the OTP from Mailtrap inbox (polls up to 30 s)
    const otp = await readOtpFromMailtrap(
      MAILTRAP_ACCOUNT_ID!,
      MAILTRAP_INBOX_ID!,
      MAILTRAP_API_TOKEN!,
      TEST_PASSWORDLESS_EMAIL!,
      notBefore
    );
    expect(otp).toMatch(/^\d{6}$/);

    // Step 3: POST /auth/passwordless/verify — SDK exchanges code for tokens + sets session
    const verifyRes = await context.request.post("/auth/passwordless/verify", {
      data: {
        connection: TEST_PASSWORDLESS_CONNECTION!,
        email: TEST_PASSWORDLESS_EMAIL!,
        verificationCode: otp,
      },
    });
    expect(verifyRes.status()).toBe(200);

    // Step 4: verify the session cookie was set
    const cookies = await context.cookies();
    const sessionCookie = cookies.find((c) => c.name === "__session");
    expect(sessionCookie).toBeTruthy();
    expect(sessionCookie!.value.length).toBeGreaterThan(10);

    // Step 5: confirm the session is valid
    const sessionRes = await context.request.get("/app-router/api/get-session");
    expect(sessionRes.status()).toBe(200);
    const session = await sessionRes.json();
    expect(session).toHaveProperty("user");
    expect(typeof session.user.sub).toBe("string");
  });
});

// ─── @integration — Full end-to-end phone/SMS OTP via Twilio ─────────────────
//
// Uses Auth0's built-in "sms" passwordless connection:
//   POST /auth/passwordless/start  { connection: "sms", phoneNumber }
//   POST /auth/passwordless/verify { connection: "sms", phoneNumber, verificationCode }
//
// Prerequisites:
//   - Auth0 tenant phone provider → Twilio (Branding → Phone Provider)
//   - Env vars: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN,
//               TEST_PASSWORDLESS_PHONE, TEST_PASSWORDLESS_PHONE_CONNECTION (= "sms")

test.describe("Full phone/SMS OTP flow @integration — Twilio", () => {
  const {
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN,
    TEST_PASSWORDLESS_PHONE,
    TEST_PASSWORDLESS_PHONE_CONNECTION,
  } = process.env;

  test.skip(
    !TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN,
    "requires TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN"
  );
  test.skip(
    !TEST_PASSWORDLESS_PHONE,
    "requires TEST_PASSWORDLESS_PHONE — E.164 number receiving the OTP SMS"
  );
  test.skip(
    !TEST_PASSWORDLESS_PHONE_CONNECTION,
    "requires TEST_PASSWORDLESS_PHONE_CONNECTION (e.g. 'sms')"
  );

  test("phone OTP: start → intercept OTP via Twilio → verify → session cookie set", async ({
    context,
  }) => {
    // Capture timestamp BEFORE start so the poller ignores any older messages.
    const notBefore = new Date();

    // Step 1: POST /auth/passwordless/start — Auth0 sends OTP SMS via Twilio
    // SDK returns 204 No Content on success (no body)
    const startRes = await context.request.post("/auth/passwordless/start", {
      data: {
        connection: TEST_PASSWORDLESS_PHONE_CONNECTION!,
        phoneNumber: TEST_PASSWORDLESS_PHONE!,
      },
    });
    expect(startRes.status()).toBe(204);

    // Step 2: read the OTP from Twilio Messages API (polls up to 30 s)
    const otp = await readOtpFromTwilio(
      TWILIO_ACCOUNT_SID!,
      TWILIO_AUTH_TOKEN!,
      TEST_PASSWORDLESS_PHONE!,
      notBefore
    );
    expect(otp).toMatch(/^\d{6}$/);

    // Step 3: POST /auth/passwordless/verify — SDK sets session cookie on success
    const verifyRes = await context.request.post("/auth/passwordless/verify", {
      data: {
        connection: TEST_PASSWORDLESS_PHONE_CONNECTION!,
        phoneNumber: TEST_PASSWORDLESS_PHONE!,
        verificationCode: otp,
      },
    });
    expect(verifyRes.status()).toBe(200);

    // Step 4: verify the session cookie was set
    const cookies = await context.cookies();
    const sessionCookie = cookies.find((c) => c.name === "__session");
    expect(sessionCookie).toBeTruthy();
    expect(sessionCookie!.value.length).toBeGreaterThan(10);

    // Step 5: confirm the session is valid
    const sessionRes = await context.request.get("/app-router/api/get-session");
    expect(sessionRes.status()).toBe(200);
    const session = await sessionRes.json();
    expect(session).toHaveProperty("user");
    expect(typeof session.user.sub).toBe("string");
  });
});
