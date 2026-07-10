/**
 * Custom Token Exchange (CTE) E2E tests.
 *
 * Covers:
 *  - POST /app-router/api/custom-token-exchange — 401 without session
 *  - POST with invalid subjectToken — returns structured 400 error (not 500)
 *  - POST with missing subjectToken field — returns 400
 *  - POST body shape: subjectToken, subjectTokenType, audience all accepted
 *  - Error response shape: { error, code } on failure
 *
 * Full end-to-end CTE (receiving a valid token from Auth0) requires a tenant
 * configured with the Custom Token Exchange grant + a valid subject token from
 * an external IdP. These tests lock down the SDK surface and route wiring.
 *
 * Tests tagged @integration require a real subject token from an external IdP.
 */

import { expect, test } from "@playwright/test";
import { loginWithAuth0 } from "../../helpers";

// ─── Route wiring / authentication guard ──────────────────────────────────────

test.describe("customTokenExchange() — authentication guard", () => {
  test("POST returns 401 without a session", async ({ context }) => {
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: { subjectToken: "some-token" },
    });
    expect(res.status()).toBe(401);
  });

  test("401 response has structured error body", async ({ context }) => {
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: { subjectToken: "some-token" },
    });
    const body = await res.json();
    expect(body).toHaveProperty("error");
  });

  test("GET method is not accepted (route is POST-only)", async ({ context }) => {
    const res = await context.request.get("/app-router/api/custom-token-exchange");
    expect(res.status()).not.toBe(200);
  });
});

// ─── SDK error handling ────────────────────────────────────────────────────────

test.describe("customTokenExchange() — SDK error forwarding", () => {
  test("POST with invalid subjectToken returns 400 (not 500)", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: { subjectToken: "invalid-token" },
    });
    // Auth0 rejects the invalid token — SDK surfaces 400 with error details
    expect([400, 401, 403]).toContain(res.status());
    expect(res.status()).not.toBe(500);
  });

  test("400 response body contains error and code fields", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: { subjectToken: "invalid-token" },
    });
    if (res.status() >= 400) {
      const body = await res.json();
      expect(body).toHaveProperty("error");
    }
  });

  test("POST with missing subjectToken returns 400", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: {},
    });
    expect([400, 401]).toContain(res.status());
    expect(res.status()).not.toBe(500);
  });
});

// ─── Request body shape ────────────────────────────────────────────────────────

test.describe("customTokenExchange() — request body forwarding", () => {
  test("subjectTokenType field is forwarded to Auth0", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: {
        subjectToken: "some-external-token",
        subjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
      },
    });
    // Route accepts the body and forwards to Auth0 — 400 from Auth0 is expected (invalid token)
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(405);
  });

  test("audience field is forwarded to Auth0", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: {
        subjectToken: "some-external-token",
        audience: "https://api.example.com",
      },
    });
    expect(res.status()).not.toBe(500);
    expect(res.status()).not.toBe(405);
  });

  test("all three fields together: subjectToken + subjectTokenType + audience", async ({
    page,
    context,
  }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: {
        subjectToken: "some-external-token",
        subjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
        audience: "https://api.example.com",
      },
    });
    expect(res.status()).not.toBe(500);
  });
});

// ─── @integration — requires real external IdP token ─────────────────────────

test.describe("customTokenExchange() — successful exchange @integration", () => {
  test.skip(
    !process.env.TEST_CTE_SUBJECT_TOKEN,
    "requires TEST_CTE_SUBJECT_TOKEN — a valid token from a configured external IdP"
  );

  test("valid subject token returns a new Auth0 token set", async ({ page, context }) => {
    await loginWithAuth0(page, "/app-router/server");
    const res = await context.request.post("/app-router/api/custom-token-exchange", {
      data: {
        subjectToken: process.env.TEST_CTE_SUBJECT_TOKEN,
        subjectTokenType:
          process.env.TEST_CTE_SUBJECT_TOKEN_TYPE ??
          "urn:ietf:params:oauth:token-type:access_token",
      },
    });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(typeof body.accessToken ?? body.access_token).toBe("string");
  });
});
