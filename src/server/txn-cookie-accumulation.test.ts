import { NextRequest } from "next/server.js";
import * as jose from "jose";
import * as oauth from "oauth4webapi";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { RESPONSE_TYPES } from "../types/connected-accounts.js";
import { isNonNavigationalRequest } from "../utils/request.js";
import { AuthClient } from "./auth-client.js";
import { RequestCookies, ResponseCookies } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionState, TransactionStore } from "./transaction-store.js";

vi.mock("oauth4webapi", async () => {
  const actual = await vi.importActual<typeof oauth>("oauth4webapi");
  return {
    ...actual,
    generateRandomState: vi.fn(),
    generateRandomNonce: vi.fn(),
    generateRandomCodeVerifier: vi.fn(),
    calculatePKCECodeChallenge: vi.fn(),
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    validateAuthResponse: vi.fn(),
    getValidatedIdTokenClaims: vi.fn(),
    processAuthorizationCodeResponse: vi.fn(),
    authorizationCodeGrantRequest: vi.fn()
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const makeTransactionState = (
  state: string,
  overrides: Partial<TransactionState> = {}
): TransactionState => ({
  nonce: "test-nonce",
  codeVerifier: "test-cv",
  responseType: RESPONSE_TYPES.CODE,
  maxAge: 3600,
  returnTo: "/",
  state,
  ...overrides
});

/** Build a RequestCookies instance pre-populated with the given name=value pairs. */
const makeRequestCookies = (pairs: Record<string, string>): RequestCookies => {
  const headers = new Headers();
  const cookieHeader = Object.entries(pairs)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
  headers.append("cookie", cookieHeader);
  return new RequestCookies(headers);
};

/** Build an empty ResponseCookies. */
const makeResponseCookies = (): ResponseCookies => {
  return new ResponseCookies(new Headers());
};

// ---------------------------------------------------------------------------
// Fix 1 — isNonNavigationalRequest
// ---------------------------------------------------------------------------

describe("Fix 1 — isNonNavigationalRequest()", () => {
  const makeReq = (headers: Record<string, string>) => {
    const req = new NextRequest("http://localhost:3000/auth/login");
    Object.entries(headers).forEach(([k, v]) => req.headers.set(k, v));
    return req;
  };

  describe("known prefetch headers — positive detection only", () => {
    it("returns true when next-router-prefetch is 1", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "next-router-prefetch": "1" }))
      ).toBe(true);
    });

    it("returns true when purpose is prefetch", () => {
      expect(isNonNavigationalRequest(makeReq({ purpose: "prefetch" }))).toBe(
        true
      );
    });

    it("returns true when sec-purpose is prefetch", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-purpose": "prefetch" }))
      ).toBe(true);
    });

    it("returns true when x-middleware-prefetch is 1", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "x-middleware-prefetch": "1" }))
      ).toBe(true);
    });
  });

  describe("requests that must not be blocked", () => {
    it("returns false for plain navigation with no prefetch headers", () => {
      expect(isNonNavigationalRequest(makeReq({ accept: "text/html" }))).toBe(
        false
      );
    });

    it("returns false for accept: text/x-component — real RSC <Link> navigation must not be blocked", () => {
      // text/x-component is sent by ALL App Router RSC requests, including a
      // genuine client-side <Link prefetch={false}> click — not just prefetches.
      expect(
        isNonNavigationalRequest(makeReq({ accept: "text/x-component" }))
      ).toBe(false);
    });

    it("returns false for sec-fetch-mode: navigate", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "navigate" }))
      ).toBe(false);
    });

    it("returns false for sec-fetch-mode: cors — legitimate fetch()/XHR must not be blocked", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "cors" }))
      ).toBe(false);
    });

    it("returns false for sec-fetch-mode: same-origin — legitimate fetch()/XHR must not be blocked", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "same-origin" }))
      ).toBe(false);
    });

    it("returns false when no headers present", () => {
      expect(isNonNavigationalRequest(makeReq({}))).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// Fix 2 — transaction cookie eviction in TransactionStore.save()
// The byte limit is fixed at 3500 bytes and not configurable. Tests exercise it
// by building transaction cookies whose combined size crosses that threshold.
// ---------------------------------------------------------------------------

// A single transaction cookie value large enough that two of them exceed the
// fixed 3500-byte limit but one does not (~1900 bytes of value each).
const BIG_VALUE = (ts: number) => `${ts}:${"j".repeat(1900)}`;

describe("Fix 2 — transaction cookie eviction in TransactionStore.save()", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  it("does not evict when no reqCookies passed (no eviction without snapshot)", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "state-no-evict";

    // With no reqCookies snapshot, eviction is skipped entirely.
    await expect(
      store.save(resCookies, makeTransactionState(state))
    ).resolves.not.toThrow();

    expect(resCookies.get(`__txn_${state}`)?.value).toBeTruthy();
  });

  it("does not evict when accumulated bytes are below the limit", async () => {
    const store = new TransactionStore({ secret });

    const existingState = "existing-state";
    const reqCookies = makeRequestCookies({
      [`__txn_${existingState}`]: "1000:short"
    });
    const resCookies = makeResponseCookies();
    const newState = "new-state";

    await store.save(resCookies, makeTransactionState(newState), reqCookies);

    // Existing cookie was not evicted (no delete set on it)
    const evicted = resCookies
      .getAll()
      .filter((c) => c.name === `__txn_${existingState}` && c.maxAge === 0);
    expect(evicted).toHaveLength(0);

    // New cookie was written
    expect(resCookies.get(`__txn_${newState}`)?.value).toBeTruthy();
  });

  it("counts the new cookie in the cap: evicts when existing is under-limit but projected total reaches it", async () => {
    const store = new TransactionStore({ secret });

    // One existing cookie sized just under 3500 bytes on its own — no eviction
    // would fire if only existing bytes were counted. The ~500-byte new cookie
    // pushes the projected total over the limit, so eviction MUST fire.
    const existingState = "existing";
    const nearLimitValue = `1000:${"j".repeat(3400)}`; // ~3413 bytes with name
    const reqCookies = makeRequestCookies({
      [`__txn_${existingState}`]: nearLimitValue
    });
    const resCookies = makeResponseCookies();

    await store.save(resCookies, makeTransactionState("newstate"), reqCookies);

    // The existing (older) cookie is evicted so the projected total stays bounded
    expect(resCookies.get(`__txn_${existingState}`)?.maxAge).toBe(0);
    // New cookie still written
    expect(resCookies.get("__txn_newstate")?.value).toBeTruthy();
  });

  it("evicts oldest cookie first when the 3500 byte limit is exceeded", async () => {
    const store = new TransactionStore({ secret });

    const olderState = "older";
    const newerState = "newer";
    // Two big cookies together exceed 3500 bytes → eviction fires and only needs
    // to remove the single oldest to get back under the limit.
    const reqCookies = makeRequestCookies({
      [`__txn_${olderState}`]: BIG_VALUE(1000),
      [`__txn_${newerState}`]: BIG_VALUE(9999)
    });
    const resCookies = makeResponseCookies();

    const newState = "newstate";
    await store.save(resCookies, makeTransactionState(newState), reqCookies);

    // Older cookie evicted first
    expect(resCookies.get(`__txn_${olderState}`)?.maxAge).toBe(0);
    // Newer cookie untouched — eviction stopped after freeing enough
    expect(resCookies.get(`__txn_${newerState}`)?.maxAge).not.toBe(0);
    // New cookie written
    expect(resCookies.get(`__txn_${newState}`)?.value).toBeTruthy();
  });

  it("evicts oldest login cookies first (FIFO by timestamp)", async () => {
    const store = new TransactionStore({ secret });

    const olderState = "older";
    const newerState = "newer";
    // Older timestamp should be evicted first once the limit is crossed.
    const reqCookies = makeRequestCookies({
      [`__txn_${olderState}`]: BIG_VALUE(1000),
      [`__txn_${newerState}`]: BIG_VALUE(9999)
    });
    const resCookies = makeResponseCookies();

    const newState = "latest";
    await store.save(resCookies, makeTransactionState(newState), reqCookies);

    // Older cookie evicted first
    expect(resCookies.get(`__txn_${olderState}`)?.maxAge).toBe(0);
    // New cookie written
    expect(resCookies.get(`__txn_${newState}`)?.value).toBeTruthy();
  });

  it("evicts legacy cookies (no timestamp prefix) as oldest (timestamp=0)", async () => {
    // Legacy format "{jwe}" has no prefix → gets timestamp 0 → oldest in FIFO
    const store = new TransactionStore({ secret });

    const legacyState = "legacy";
    const newerState = "newer";
    const reqCookies = makeRequestCookies({
      [`__txn_${legacyState}`]: "r".repeat(1900), // legacy bare value, no "{ts}:"
      [`__txn_${newerState}`]: BIG_VALUE(9999),
      other_cookie: "keep_me"
    });
    const resCookies = makeResponseCookies();

    const newState = "newstate";
    await store.save(resCookies, makeTransactionState(newState), reqCookies);

    // Legacy cookie evicted (ts=0, oldest)
    expect(resCookies.get(`__txn_${legacyState}`)?.maxAge).toBe(0);
    // New cookie written
    expect(resCookies.get(`__txn_${newState}`)?.value).toBeTruthy();
    // Non-txn cookie untouched
    expect(resCookies.get("other_cookie")).toBeUndefined();
  });

  it("only evicts cookies matching the configured prefix", async () => {
    const customPrefix = "__my_txn_";
    const store = new TransactionStore({
      secret,
      cookieOptions: { prefix: customPrefix }
    });

    // Two big custom-prefix cookies exceed the limit; a same-sized cookie with a
    // different prefix must not be counted toward the budget or evicted.
    const reqCookies = makeRequestCookies({
      [`${customPrefix}state1`]: BIG_VALUE(1000),
      [`${customPrefix}state2`]: BIG_VALUE(2000),
      __txn_other: BIG_VALUE(1000) // different prefix — should NOT be evicted
    });
    const resCookies = makeResponseCookies();

    await store.save(
      resCookies,
      makeTransactionState("new", { state: "new" }),
      reqCookies
    );

    // Oldest custom-prefix cookie evicted
    expect(resCookies.get(`${customPrefix}state1`)?.maxAge).toBe(0);
    // __txn_other has a different prefix — not touched by this store
    expect(resCookies.get("__txn_other")).toBeUndefined();
  });

  it("does not expose maxSizeBytes as a configurable option", () => {
    // Type-level guarantee that the option was removed; passing it is a no-op
    // and the fixed limit still governs eviction.
    const store = new TransactionStore({
      secret,
      // @ts-expect-error maxSizeBytes is no longer a supported option
      cookieOptions: { maxSizeBytes: 1 }
    });
    expect(store).toBeInstanceOf(TransactionStore);
  });

  it("cookie value is encoded as '{ts}:{jwe}'", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "login-state";

    await store.save(resCookies, makeTransactionState(state));

    const value = resCookies.get(`__txn_${state}`)?.value ?? "";
    const colonIdx = value.indexOf(":");
    expect(colonIdx).toBeGreaterThan(0);
    const ts = parseInt(value.slice(0, colonIdx));
    expect(ts).toBeGreaterThan(0);
    expect(value.slice(colonIdx + 1)).toBeTruthy();
  });

  it("cookie gets full maxAge (1h default)", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "full-ttl";

    await store.save(resCookies, makeTransactionState(state));

    expect(resCookies.get(`__txn_${state}`)?.maxAge).toBe(3600);
  });

  it("get() strips '{ts}:' prefix before decrypting", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "get-test";

    await store.save(resCookies, makeTransactionState(state));

    const encodedValue = resCookies.get(`__txn_${state}`)?.value ?? "";
    expect(encodedValue.match(/^\d+:/)).toBeTruthy();

    const reqCookies = makeRequestCookies({ [`__txn_${state}`]: encodedValue });
    const result = await store.get(reqCookies, state);

    expect(result).not.toBeNull();
    expect(result?.payload?.state).toBe(state);
  });
});

// ---------------------------------------------------------------------------
// Fix 3 — Dormant early-return removed for enableParallelTransactions: false
// ---------------------------------------------------------------------------

describe("Fix 3 — No lock-out in single-transaction mode", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  it("overwrites stale __txn_ cookie when user retries login after abandonment", async () => {
    const store = new TransactionStore({
      secret,
      enableParallelTransactions: false
    });

    // Simulate stale cookie from abandoned login sitting in browser
    const reqCookies = makeRequestCookies({ __txn_: "stale_jwe_value" });
    const resCookies = makeResponseCookies();

    const newState = "new-login-state";

    // Before Fix 3 this would return early and skip writing — now it must overwrite
    await store.save(resCookies, makeTransactionState(newState), reqCookies);

    const written = resCookies.get("__txn_");
    expect(written).toBeDefined();
    expect(written?.value).not.toBe("stale_jwe_value");
    expect(written?.value).toBeTruthy();
    expect(written?.maxAge).not.toBe(0);
  });

  it("uses fixed cookie name __txn_ regardless of state value", async () => {
    const store = new TransactionStore({
      secret,
      enableParallelTransactions: false
    });

    const resCookies = makeResponseCookies();
    const state = "some-state-value";
    await store.save(resCookies, makeTransactionState(state));

    // Cookie name must be "__txn_", not "__txn_{state}"
    expect(resCookies.get("__txn_")).toBeDefined();
    expect(resCookies.get(`__txn_${state}`)).toBeUndefined();
  });

  it("creates unique __txn_{state} cookies in parallel mode (baseline)", async () => {
    const store = new TransactionStore({
      secret,
      enableParallelTransactions: true
    });

    const resCookies = makeResponseCookies();
    const stateA = "stateA";
    const stateB = "stateB";

    await store.save(resCookies, makeTransactionState(stateA));
    await store.save(resCookies, makeTransactionState(stateB));

    expect(resCookies.get(`__txn_${stateA}`)?.value).toBeTruthy();
    expect(resCookies.get(`__txn_${stateB}`)?.value).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Fix 4 — Callback cleanup: delete only the completing flow's cookie
// ---------------------------------------------------------------------------

describe("Fix 4 — callback cleanup: delete(state)", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  it("deletes only the completing flow's cookie, leaves other real login cookies untouched", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    resCookies.set("__txn_stateA", "1000:jwe_a");
    resCookies.set("__txn_stateB", "2000:jwe_b");

    await store.delete(resCookies, "stateA");

    expect(resCookies.get("__txn_stateA")?.maxAge).toBe(0);
    expect(resCookies.get("__txn_stateB")?.value).toBe("2000:jwe_b");
    expect(resCookies.get("__txn_stateB")?.maxAge).not.toBe(0);
  });

  it("does not throw when deleting a non-existent state", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();

    await expect(
      store.delete(resCookies, "nonexistent-state")
    ).resolves.not.toThrow();
  });

  it("single-transaction mode: delete(state) resolves to __txn_ regardless of state value", async () => {
    const store = new TransactionStore({
      secret,
      enableParallelTransactions: false
    });
    const resCookies = makeResponseCookies();
    resCookies.set("__txn_", "1000:stale_jwe");

    await store.delete(resCookies, "any-state-value");

    expect(resCookies.get("__txn_")?.maxAge).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Integration tests — handler() prefetch guard + handleCallback sweep
// These cover the three checklist items that require AuthClient + real flows.
// ---------------------------------------------------------------------------

describe("Integration — prefetch guard and callback cleanup via AuthClient", () => {
  const domain = "test.auth0.com";
  const clientId = "test-client-id";
  let keyPair: jose.GenerateKeyPairResult;
  let secret: string;

  // Minimal mock authorization server used across all integration tests.
  const makeFetch = () =>
    vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = new URL(input instanceof Request ? input.url : input);
      if (url.pathname === "/.well-known/openid-configuration") {
        return Response.json({
          issuer: `https://${domain}/`,
          authorization_endpoint: `https://${domain}/authorize`,
          token_endpoint: `https://${domain}/oauth/token`,
          jwks_uri: `https://${domain}/.well-known/jwks.json`
        });
      }
      if (url.pathname === "/.well-known/jwks.json") {
        return Response.json({
          keys: [
            {
              ...(await jose.exportJWK(keyPair.publicKey)),
              kid: "k1",
              use: "sig"
            }
          ]
        });
      }
      if (url.pathname === "/oauth/token") {
        const idToken = await new jose.SignJWT({
          sub: "user123",
          sid: "sid123",
          nonce: "test-nonce",
          aud: clientId,
          iss: `https://${domain}/`
        })
          .setProtectedHeader({ alg: "RS256" })
          .setIssuedAt()
          .setExpirationTime("2h")
          .sign(keyPair.privateKey);
        return Response.json({
          token_type: "Bearer",
          access_token: "at_123",
          id_token: idToken,
          expires_in: 3600
        });
      }
      return new Response(null, { status: 404 });
    });

  const makeAuthClient = () => {
    const transactionStore = new TransactionStore({ secret });
    const sessionStore = new StatelessSessionStore({ secret });
    return new AuthClient({
      domain,
      clientId,
      clientSecret: "test-secret",
      appBaseUrl: "http://localhost:3000",
      secret,
      transactionStore,
      sessionStore,
      routes: getDefaultRoutes(),
      fetch: makeFetch()
    });
  };

  beforeEach(async () => {
    vi.clearAllMocks();
    secret = await generateSecret(32);
    keyPair = await jose.generateKeyPair("RS256");

    vi.mocked(oauth.generateRandomState).mockReturnValue("test-state");
    vi.mocked(oauth.generateRandomNonce).mockReturnValue("test-nonce");
    vi.mocked(oauth.generateRandomCodeVerifier).mockReturnValue("cv");
    vi.mocked(oauth.calculatePKCECodeChallenge).mockResolvedValue("cc");
    vi.mocked(oauth.validateAuthResponse).mockReturnValue(
      new URLSearchParams("code=auth_code&state=test-state")
    );
    vi.mocked(oauth.discoveryRequest).mockResolvedValue(new Response());
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: `https://${domain}/`,
      authorization_endpoint: `https://${domain}/authorize`,
      token_endpoint: `https://${domain}/oauth/token`,
      jwks_uri: `https://${domain}/.well-known/jwks.json`
    } as oauth.AuthorizationServer);
    vi.mocked(oauth.authorizationCodeGrantRequest).mockResolvedValue(
      new Response()
    );
    vi.mocked(oauth.processAuthorizationCodeResponse).mockResolvedValue({
      token_type: "Bearer",
      access_token: "at_123",
      id_token: "id_token_placeholder",
      expires_in: 3600
    } as oauth.TokenEndpointResponse);
    vi.mocked(oauth.getValidatedIdTokenClaims).mockReturnValue({
      sub: "user123",
      sid: "sid123",
      nonce: "test-nonce",
      aud: clientId,
      iss: `https://${domain}/`,
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 3600
    });
  });

  it("Fix 1 — known prefetch header returns 401 and no __txn_* cookie is written", async () => {
    const authClient = makeAuthClient();
    const req = new NextRequest("http://localhost:3000/auth/login", {
      headers: { "next-router-prefetch": "1" }
    });

    const res = await authClient.handler(req);

    expect(res.status).toBe(401);
    const txnCookies = res.cookies
      .getAll()
      .filter((c) => c.name.startsWith("__txn_") && c.maxAge !== 0);
    expect(txnCookies).toHaveLength(0);
  });

  it("Fix 1 — real navigation is allowed through and __txn_* cookie is written", async () => {
    const authClient = makeAuthClient();
    const req = new NextRequest("http://localhost:3000/auth/login", {
      headers: { "sec-fetch-mode": "navigate" }
    });

    const res = await authClient.handler(req);

    expect(res.status).toBeGreaterThanOrEqual(300);
    expect(res.status).toBeLessThan(400);
    const txnCookies = res.cookies
      .getAll()
      .filter((c) => c.name.startsWith("__txn_") && (c.maxAge ?? 0) > 0);
    expect(txnCookies.length).toBeGreaterThan(0);
  });

  it("Fix 4 — handleCallback deletes only the completing cookie, leaves Tab B cookie untouched", async () => {
    const authClient = makeAuthClient();

    const loginRes = await authClient.handleLogin(
      new NextRequest("http://localhost:3000/auth/login")
    );
    const state = new URL(loginRes.headers.get("Location")!).searchParams.get(
      "state"
    )!;
    const txnCookie = loginRes.cookies.get(`__txn_${state}`);
    expect(txnCookie).toBeDefined();
    expect(txnCookie!.value).toMatch(/^\d+:/);

    const callbackReq = new NextRequest(
      `http://localhost:3000/auth/callback?code=auth_code&state=${state}`
    );
    callbackReq.cookies.set(`__txn_${state}`, txnCookie!.value);
    callbackReq.cookies.set("__txn_tabB", "9999999999:tab_b_real_login_jwe");

    const callbackRes = await authClient.handleCallback(callbackReq);

    expect(callbackRes.status).toBeGreaterThanOrEqual(300);
    expect(callbackRes.status).toBeLessThan(400);

    // Completing cookie deleted
    expect(callbackRes.cookies.get(`__txn_${state}`)?.maxAge).toBe(0);
    // Tab B real login cookie must NOT be deleted
    expect(callbackRes.cookies.get("__txn_tabB")?.maxAge).not.toBe(0);
    // Session written
    expect(callbackRes.cookies.get("__session")?.value).toBeTruthy();
  });
});
