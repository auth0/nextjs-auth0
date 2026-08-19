/**
 * Offline renewal and cookie chunking tests (Tier 2: O15-O17).
 *
 * Tests silent token renewal on expiry, cookie chunking behavior, and
 * metadata set-once retention across renewal. Runs against E2E_ANON_MOCK=1
 * server on :3001.
 */
import { expect, test } from "@playwright/test";

import { createAnon, readAnon, setScenario } from "./helpers";

test.beforeEach(async ({ context }) => {
  await setScenario(context.request, "success");
});

test.afterEach(async ({ context }) => {
  // Reset mock scenario to success to prevent error leakage across tests
  await setScenario(context.request, "success");
});

test("O15: silent renewal on expiry returns fresh token", async ({
  context
}) => {
  // Create a session with expired token (expires_in: -10)
  await setScenario(context.request, "expired");
  const createRes = await createAnon(context.request);
  expect(createRes.status()).toBe(201);

  const createBody = await createRes.json();
  const originalExpiresAt = createBody.expiresAt;

  // Confirm token is expired (expiresAt in the past)
  expect(originalExpiresAt).toBeLessThan(Date.now());

  // Switch to success scenario for renewal
  await setScenario(context.request, "success");

  // GET /auth/anonymous-session triggers silent renewal when expires_at <= now
  const { status, json } = await readAnon(context.request);
  expect(status).toBe(200);

  // Renewed token has strictly greater expiresAt (proves fresh expiry, not stale re-read)
  expect(json.expiresAt).toBeGreaterThan(originalExpiresAt);
});

test("O16: single-cookie storage for typical payloads", async ({ context }) => {
  // Cookie chunking threshold is 3500 bytes. Normal payloads (session_token +
  // access_token + metadata encrypted) fit in a single cookie. Metadata is
  // capped at 1KB, and tokens are small (~200-400 bytes), so total encrypted
  // payload is <3500 bytes. Chunking (auth0_anon__0, auth0_anon__1) cannot be
  // triggered through the public create path. SDK unit tests (src cookies test)
  // cover >4KB chunking logic.

  await setScenario(context.request, "success");

  // Create session with substantial metadata (near the 1KB cap)
  const res = await createAnon(context.request, {
    metadata: { blob: "y".repeat(900) }
  });
  expect(res.status()).toBe(201);

  // Verify single cookie (auth0_anon) without chunking (__0 / __1)
  const cookies = await context.cookies();
  const anonCookie = cookies.find((c) => c.name === "auth0_anon");
  const chunkCookies = cookies.filter((c) => c.name.match(/^auth0_anon__\d+$/));

  expect(anonCookie).toBeDefined();
  expect(chunkCookies.length).toBe(0);

  // Confirm session readable
  const { status } = await readAnon(context.request);
  expect(status).toBe(200);
});

test("O17: metadata set-once retained across renewal", async ({ context }) => {
  // Create session with expired token and metadata (expires_in: -10, already expired at create).
  // This session's token is immediately expired, so the next read will trigger renewal.
  await setScenario(context.request, "expired");
  const createRes = await createAnon(context.request, {
    metadata: { cart_id: "orig" }
  });
  expect(createRes.status()).toBe(201);

  const createBody = await createRes.json();
  expect(createBody.metadata.cart_id).toBe("orig");

  // Switch to success scenario so the upcoming renewal returns a fresh valid token.
  // The mock RENEW response (in lib/mock/anon-mock-fetch.ts) deliberately OMITS metadata.
  await setScenario(context.request, "success");

  // GET /auth/anonymous-session triggers silent renewal because cookie expires_at <= now.
  // The mock renew response has NO metadata field. The only way cart_id survives is the SDK
  // retaining prior metadata from the encrypted cookie payload across renewal (set-once proof).
  const { status, json } = await readAnon(context.request);
  expect(status).toBe(200);

  // Original metadata persists after renewal (set-once semantics). Since the mock renew
  // response omits metadata, this assertion proves the SDK retained it from the cookie.
  expect(json.metadata.cart_id).toBe("orig");
});
