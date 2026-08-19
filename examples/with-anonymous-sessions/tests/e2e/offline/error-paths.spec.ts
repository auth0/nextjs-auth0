/**
 * Offline error-path tests (Tier 2: O9-O14).
 *
 * Validates error scenario mapping (API + UI) and client-side metadata
 * validation. Runs against E2E_ANON_MOCK=1 server on :3001.
 */
import { expect, test } from "@playwright/test";

import { createAnon, setScenario } from "./helpers";

test.afterEach(async ({ context }) => {
  // Reset mock scenario to success to prevent error leakage across tests
  await setScenario(context.request, "success");
});

test("O9: feature_not_enabled returns 403 with UI error banner", async ({
  context
}) => {
  await setScenario(context.request, "feature_not_enabled");

  // API-level: create route returns 403 with code "feature_not_enabled"
  const res = await createAnon(context.request);
  expect(res.status()).toBe(403);

  const body = await res.json();
  expect(body.code).toBe("feature_not_enabled");

  // UI-level: demo page surfaces the error banner
  const page = await context.newPage();
  await page.goto("/");

  const guestButton = page.getByRole("button", { name: "Enter as Guest" });
  await guestButton.click();

  // Error banner should appear with tenant misconfiguration message
  // (app/page.tsx L38-44 shows custom diagnostic, not the raw code)
  const errorBanner = page.locator(".error-banner");
  await expect(errorBanner).toBeVisible({ timeout: 5_000 });
  await expect(errorBanner).toContainText("Tenant not configured");
  await expect(errorBanner).toContainText("oidc_conformant: true");
});

test("O10: unauthorized_client returns 403", async ({ context }) => {
  await setScenario(context.request, "unauthorized_client");

  const res = await createAnon(context.request);
  expect(res.status()).toBe(403);

  const body = await res.json();
  expect(body.code).toBe("unauthorized_client");
});

test("O11: invalid_target returns 400", async ({ context }) => {
  await setScenario(context.request, "invalid_target");

  const res = await createAnon(context.request);
  expect(res.status()).toBe(400);

  const body = await res.json();
  expect(body.code).toBe("invalid_target");
});

test("O12: invalid_scope returns 400", async ({ context }) => {
  await setScenario(context.request, "invalid_scope");

  const res = await createAnon(context.request);
  expect(res.status()).toBe(400);

  const body = await res.json();
  expect(body.code).toBe("invalid_scope");
});

test("O13: server_error returns 500", async ({ context }) => {
  await setScenario(context.request, "server_error");

  const res = await createAnon(context.request);
  expect(res.status()).toBe(500);

  const body = await res.json();
  expect(body.code).toBe("server_error");
});

test("O14: metadata >1KB rejected client-side before network call", async ({
  context
}) => {
  // SDK client-side validation throws AnonymousSessionError with code
  // "metadata_too_large" BEFORE any network call. The mock never sees this
  // request — scenario remains "success".
  await setScenario(context.request, "success");

  // Serialize to >1KB (2000 chars + JSON overhead)
  const largeMetadata = { blob: "x".repeat(2000) };

  const res = await createAnon(context.request, { metadata: largeMetadata });

  // SDK validation error mapped to 400 by getStatusForAnonymousError default
  expect(res.status()).toBe(400);

  const body = await res.json();
  expect(body.code).toBe("metadata_too_large");

  // Confirm mock was not involved: subsequent create with valid metadata
  // succeeds without needing to reset scenario
  const validRes = await createAnon(context.request, {
    metadata: { cart_id: "valid" }
  });
  expect(validRes.status()).toBe(201);
});
