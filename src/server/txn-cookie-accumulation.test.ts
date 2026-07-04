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

  describe("sec-fetch-mode (primary signal)", () => {
    it("returns false for sec-fetch-mode: navigate (real navigation)", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "navigate" }))
      ).toBe(false);
    });

    it("returns true for sec-fetch-mode: cors (Next.js prefetch)", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "cors" }))
      ).toBe(true);
    });

    it("returns true for sec-fetch-mode: no-cors", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "no-cors" }))
      ).toBe(true);
    });

    it("returns true for sec-fetch-mode: same-origin (XHR / fetch)", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "sec-fetch-mode": "same-origin" }))
      ).toBe(true);
    });
  });

  describe("fallback headers (sec-fetch-mode absent)", () => {
    it("returns true when next-router-prefetch is 1", () => {
      expect(
        isNonNavigationalRequest(makeReq({ "next-router-prefetch": "1" }))
      ).toBe(true);
    });

    it("returns true when accept is text/x-component", () => {
      expect(
        isNonNavigationalRequest(makeReq({ accept: "text/x-component" }))
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

    it("returns false when no prefetch headers are present (plain request)", () => {
      expect(isNonNavigationalRequest(makeReq({ accept: "text/html" }))).toBe(
        false
      );
    });
  });

  describe("sec-fetch-mode takes precedence over fallbacks", () => {
    it("returns false when sec-fetch-mode is navigate even if next-router-prefetch is 1", () => {
      expect(
        isNonNavigationalRequest(
          makeReq({
            "sec-fetch-mode": "navigate",
            "next-router-prefetch": "1"
          })
        )
      ).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// Fix 2 — maxSizeBytes eviction in TransactionStore.save()
// ---------------------------------------------------------------------------

describe("Fix 2 — maxSizeBytes eviction in TransactionStore.save()", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  it("does not evict when no reqCookies passed (no eviction without snapshot)", async () => {
    const store = new TransactionStore({
      secret,
      cookieOptions: { maxSizeBytes: 10 }
    });
    const resCookies = makeResponseCookies();
    const state = "state-no-evict";

    // Even with a tiny maxSizeBytes, passing no reqCookies skips eviction
    await expect(
      store.save(resCookies, makeTransactionState(state))
    ).resolves.not.toThrow();

    expect(resCookies.get(`__txn_${state}`)?.value).toBeTruthy();
  });

  it("does not evict when accumulated bytes are below maxSizeBytes", async () => {
    const store = new TransactionStore({
      secret,
      cookieOptions: { maxSizeBytes: 99999 }
    });

    const existingState = "existing-state";
    const reqCookies = makeRequestCookies({
      [`__txn_${existingState}`]: "short"
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

  it("phase-1 evicts prefetch cookies first, leaves real login cookies untouched when phase-1 sufficient", async () => {
    // Set maxSizeBytes just above the real login cookie size so that phase-1
    // (evicting only prefetch cookies) frees enough to get under the threshold,
    // without needing to touch the real login cookie.
    const pfState1 = "pf1";
    const pfState2 = "pf2";
    const realState = "real";
    const pfValue1 = "p:short_jwe_1";
    const pfValue2 = "p:short_jwe_2";
    const realValue = "1000000000:real_jwe_value";

    // Calculate actual byte sizes so we can set maxSizeBytes precisely.
    const enc = new TextEncoder();
    const pfBytes1 = enc.encode(`__txn_${pfState1}=${pfValue1}`).length;
    const pfBytes2 = enc.encode(`__txn_${pfState2}=${pfValue2}`).length;
    const realBytes = enc.encode(`__txn_${realState}=${realValue}`).length;
    const totalBytes = pfBytes1 + pfBytes2 + realBytes;

    // maxSizeBytes = totalBytes - pfBytes1 - pfBytes2 + 1:
    // triggers eviction, but phase-1 (freeing pfBytes1 + pfBytes2) is enough.
    const maxSizeBytes = totalBytes - pfBytes1 - pfBytes2 + 1;

    const store = new TransactionStore({
      secret,
      cookieOptions: { maxSizeBytes }
    });

    const reqCookies = makeRequestCookies({
      [`__txn_${pfState1}`]: pfValue1,
      [`__txn_${pfState2}`]: pfValue2,
      [`__txn_${realState}`]: realValue
    });
    const resCookies = makeResponseCookies();

    const newState = "newstate";
    await store.save(resCookies, makeTransactionState(newState), reqCookies);

    // Prefetch cookies evicted
    expect(resCookies.get(`__txn_${pfState1}`)?.maxAge).toBe(0);
    expect(resCookies.get(`__txn_${pfState2}`)?.maxAge).toBe(0);

    // Real login cookie untouched (phase-1 freed enough)
    expect(resCookies.get(`__txn_${realState}`)?.maxAge).not.toBe(0);

    // New cookie written
    expect(resCookies.get(`__txn_${newState}`)?.value).toBeTruthy();
  });

  it("phase-2 evicts oldest real login cookies first when phase-1 insufficient", async () => {
    const store = new TransactionStore({
      secret,
      cookieOptions: { maxSizeBytes: 1 }
    });

    const olderState = "older";
    const newerState = "newer";
    // Older timestamp should be evicted first
    const reqCookies = makeRequestCookies({
      [`__txn_${olderState}`]: "1000:jwe_older",
      [`__txn_${newerState}`]: "9999:jwe_newer"
    });
    const resCookies = makeResponseCookies();

    const newState = "latest";
    await store.save(resCookies, makeTransactionState(newState), reqCookies);

    // Older cookie evicted first
    expect(resCookies.get(`__txn_${olderState}`)?.maxAge).toBe(0);
    // New cookie written
    expect(resCookies.get(`__txn_${newState}`)?.value).toBeTruthy();
  });

  it("evicts legacy cookies (no prefix) in phase-2 as oldest (timestamp=0)", async () => {
    // Legacy format "{jwe}" has no prefix → gets timestamp 0 → oldest in FIFO
    const store = new TransactionStore({
      secret,
      cookieOptions: { maxSizeBytes: 1 }
    });

    const legacyState = "legacy";
    const newerState = "newer";
    const reqCookies = makeRequestCookies({
      [`__txn_${legacyState}`]: "raw_jwe_no_prefix",
      [`__txn_${newerState}`]: "9999:jwe_newer",
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
      cookieOptions: { maxSizeBytes: 1, prefix: customPrefix }
    });

    const reqCookies = makeRequestCookies({
      [`${customPrefix}state1`]: "p:prefetch_jwe",
      __txn_other: "1000:other_jwe" // different prefix — should NOT be evicted
    });
    const resCookies = makeResponseCookies();
    resCookies.set(`${customPrefix}state1`, "p:prefetch_jwe");
    resCookies.set("__txn_other", "1000:other_jwe");

    await store.save(
      resCookies,
      makeTransactionState("new", { state: "new" }),
      reqCookies
    );

    expect(resCookies.get(`${customPrefix}state1`)?.maxAge).toBe(0);
    // __txn_other has a different prefix — not touched by this store
    expect(resCookies.get("__txn_other")?.value).toBe("1000:other_jwe");
  });

  it("real login cookie value is encoded as '{ts}:{jwe}'", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "real-login-state";

    await store.save(resCookies, makeTransactionState(state), undefined, false);

    const value = resCookies.get(`__txn_${state}`)?.value ?? "";
    const colonIdx = value.indexOf(":");
    expect(colonIdx).toBeGreaterThan(0);
    const ts = parseInt(value.slice(0, colonIdx));
    expect(ts).toBeGreaterThan(0); // epoch timestamp
    expect(value.slice(colonIdx + 1)).toBeTruthy(); // JWE after colon
  });

  it("prefetch cookie value is encoded as 'p:{jwe}'", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "prefetch-state";

    await store.save(resCookies, makeTransactionState(state), undefined, true);

    const value = resCookies.get(`__txn_${state}`)?.value ?? "";
    expect(value.startsWith("p:")).toBe(true);
    expect(value.slice(2)).toBeTruthy(); // JWE after "p:"
  });

  it("prefetch cookie gets maxAge of 60s", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "prefetch-short-ttl";

    await store.save(resCookies, makeTransactionState(state), undefined, true);

    const cookie = resCookies.get(`__txn_${state}`);
    expect(cookie?.maxAge).toBe(60);
  });

  it("real login cookie gets full maxAge (1h default)", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "real-full-ttl";

    await store.save(resCookies, makeTransactionState(state), undefined, false);

    const cookie = resCookies.get(`__txn_${state}`);
    expect(cookie?.maxAge).toBe(3600);
  });

  it("get() strips 'p:' prefix before decrypting prefetch cookie", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "pf-get-test";

    await store.save(resCookies, makeTransactionState(state), undefined, true);

    const encodedValue = resCookies.get(`__txn_${state}`)?.value ?? "";
    expect(encodedValue.startsWith("p:")).toBe(true);

    const reqCookies = makeRequestCookies({ [`__txn_${state}`]: encodedValue });
    const result = await store.get(reqCookies, state);

    expect(result).not.toBeNull();
    expect(result?.payload?.state).toBe(state);
  });

  it("get() strips '{ts}:' prefix before decrypting real login cookie", async () => {
    const store = new TransactionStore({ secret });
    const resCookies = makeResponseCookies();
    const state = "real-get-test";

    await store.save(resCookies, makeTransactionState(state), undefined, false);

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
// Fix 4 — Targeted callback cleanup: sweep prefetch + delete only completing cookie
// ---------------------------------------------------------------------------

describe("Fix 4 — targeted cleanup: deletePrefetchCookies + delete(state)", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
  });

  describe("deletePrefetchCookies()", () => {
    it("deletes all 'p:' prefetch cookies, leaves real login cookies untouched", async () => {
      const store = new TransactionStore({ secret });
      const reqCookies = makeRequestCookies({
        __txn_pf1: "p:jwe_prefetch_1",
        __txn_pf2: "p:jwe_prefetch_2",
        __txn_real: "1000000000:jwe_real_login"
      });
      const resCookies = makeResponseCookies();

      await store.deletePrefetchCookies(reqCookies, resCookies);

      expect(resCookies.get("__txn_pf1")?.maxAge).toBe(0);
      expect(resCookies.get("__txn_pf2")?.maxAge).toBe(0);
      // Real login cookie must NOT be touched
      expect(resCookies.get("__txn_real")?.maxAge).not.toBe(0);
    });

    it("does not touch non-txn cookies", async () => {
      const store = new TransactionStore({ secret });
      const reqCookies = makeRequestCookies({
        __txn_pf1: "p:jwe_pf",
        __session: "session_value"
      });
      const resCookies = makeResponseCookies();
      resCookies.set("__session", "session_value");

      await store.deletePrefetchCookies(reqCookies, resCookies);

      expect(resCookies.get("__txn_pf1")?.maxAge).toBe(0);
      expect(resCookies.get("__session")?.value).toBe("session_value");
    });

    it("does not throw when no prefetch cookies exist", async () => {
      const store = new TransactionStore({ secret });
      const reqCookies = makeRequestCookies({
        __txn_real: "1000000000:jwe_real"
      });
      const resCookies = makeResponseCookies();

      await expect(
        store.deletePrefetchCookies(reqCookies, resCookies)
      ).resolves.not.toThrow();
    });
  });

  describe("delete(state)", () => {
    it("deletes only the specific __txn_{state} cookie", async () => {
      const store = new TransactionStore({ secret });
      const resCookies = makeResponseCookies();
      resCookies.set("__txn_stateA", "1000:jwe_a"); // completing flow
      resCookies.set("__txn_stateB", "2000:jwe_b"); // Tab B — must survive

      await store.delete(resCookies, "stateA");

      expect(resCookies.get("__txn_stateA")?.maxAge).toBe(0);
      // Tab B's real login cookie must not be touched
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
  });

  describe("combined: sweep prefetch + delete completing cookie — multi-tab safe", () => {
    it("sweeps prefetch cookies and deletes only the completing flow's cookie, leaving Tab B untouched", async () => {
      const store = new TransactionStore({ secret });

      // Tab A completing login
      const completingState = "tabA-state";
      // Tab B mid-login under different account
      const otherRealState = "tabB-state";
      // Accumulated prefetch garbage
      const pfState1 = "pf-orphan-1";
      const pfState2 = "pf-orphan-2";

      const reqCookies = makeRequestCookies({
        [`__txn_${completingState}`]: "1000:jwe_tabA",
        [`__txn_${otherRealState}`]: "2000:jwe_tabB",
        [`__txn_${pfState1}`]: "p:jwe_pf1",
        [`__txn_${pfState2}`]: "p:jwe_pf2"
      });
      const resCookies = makeResponseCookies();

      await store.deletePrefetchCookies(reqCookies, resCookies);
      await store.delete(resCookies, completingState);

      // Completing cookie deleted
      expect(resCookies.get(`__txn_${completingState}`)?.maxAge).toBe(0);
      // Prefetch cookies swept
      expect(resCookies.get(`__txn_${pfState1}`)?.maxAge).toBe(0);
      expect(resCookies.get(`__txn_${pfState2}`)?.maxAge).toBe(0);
      // Tab B's real login cookie must be untouched
      expect(resCookies.get(`__txn_${otherRealState}`)?.maxAge).not.toBe(0);
    });

    it("single-transaction mode: delete(state) resolves to __txn_ regardless of state value", async () => {
      const store = new TransactionStore({
        secret,
        enableParallelTransactions: false
      });
      const resCookies = makeResponseCookies();
      resCookies.set("__txn_", "1000:stale_jwe");

      // state value is ignored in single mode — always resolves to "__txn_"
      await store.delete(resCookies, "any-state-value");

      expect(resCookies.get("__txn_")?.maxAge).toBe(0);
    });
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

  const makeAuthClient = (
    opts: { dangerouslyAllowLoginPrefetch?: boolean } = {}
  ) => {
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
      fetch: makeFetch(),
      ...opts
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

  // Checklist: "Load bugs/txn-accumulation while logged out → no __txn_* cookies created"
  it("Fix 1 — prefetch request returns 401 and no __txn_* cookie is written (guard on, default)", async () => {
    const authClient = makeAuthClient();
    const req = new NextRequest("http://localhost:3000/auth/login", {
      headers: { "sec-fetch-mode": "cors" } // prefetch signal
    });

    const res = await authClient.handler(req);

    expect(res.status).toBe(401);
    const txnCookies = res.cookies
      .getAll()
      .filter((c) => c.name.startsWith("__txn_") && c.maxAge !== 0);
    expect(txnCookies).toHaveLength(0);
  });

  // Checklist: "Set dangerouslyAllowLoginPrefetch: true → 4 __txn_* cookies appear"
  it("Fix 1 — prefetch request is allowed through and __txn_* cookie is written (guard off)", async () => {
    const authClient = makeAuthClient({ dangerouslyAllowLoginPrefetch: true });
    const req = new NextRequest("http://localhost:3000/auth/login", {
      headers: { "sec-fetch-mode": "cors" } // same prefetch signal
    });

    const res = await authClient.handler(req);

    // Should redirect to Auth0 (3xx), not return 401
    expect(res.status).toBeGreaterThanOrEqual(300);
    expect(res.status).toBeLessThan(400);
    const txnCookies = res.cookies
      .getAll()
      .filter((c) => c.name.startsWith("__txn_") && (c.maxAge ?? 0) > 0);
    expect(txnCookies.length).toBeGreaterThan(0);
  });

  // Checklist: "Complete login → completing txn + prefetch orphans deleted, other real logins untouched"
  it("Fix 4 — handleCallback deletes completing cookie + sweeps prefetch orphans, leaves real Tab B cookie", async () => {
    const transactionStore = new TransactionStore({ secret });
    const sessionStore = new StatelessSessionStore({ secret });
    const authClient = new AuthClient({
      domain,
      clientId,
      clientSecret: "test-secret",
      appBaseUrl: "http://localhost:3000",
      secret,
      transactionStore,
      sessionStore,
      routes: getDefaultRoutes(),
      fetch: makeFetch()
      // dangerouslyAllowLoginPrefetch: false (default)
    });

    // Step 1: login to get a real transaction cookie
    const loginRes = await authClient.handleLogin(
      new NextRequest("http://localhost:3000/auth/login")
    );
    const state = new URL(loginRes.headers.get("Location")!).searchParams.get(
      "state"
    )!;
    const txnCookie = loginRes.cookies.get(`__txn_${state}`);
    expect(txnCookie).toBeDefined();
    // Verify login cookie has timestamp-prefixed value (real login, not prefetch)
    expect(txnCookie!.value).toMatch(/^\d+:/);

    // Step 2: build callback request:
    //   - completing flow's cookie
    //   - two prefetch orphans (value prefix "p:")
    //   - one real in-flight login from Tab B (must survive)
    const callbackReq = new NextRequest(
      `http://localhost:3000/auth/callback?code=auth_code&state=${state}`
    );
    callbackReq.cookies.set(`__txn_${state}`, txnCookie!.value);
    callbackReq.cookies.set("__txn_orphan_pf1", "p:prefetch_jwe_1");
    callbackReq.cookies.set("__txn_orphan_pf2", "p:prefetch_jwe_2");
    callbackReq.cookies.set("__txn_tabB", "9999999999:tab_b_real_login_jwe");

    const callbackRes = await authClient.handleCallback(callbackReq);

    expect(callbackRes.status).toBeGreaterThanOrEqual(300);
    expect(callbackRes.status).toBeLessThan(400);

    // Completing cookie must be deleted
    expect(callbackRes.cookies.get(`__txn_${state}`)?.maxAge).toBe(0);
    // Prefetch orphans must be deleted
    expect(callbackRes.cookies.get("__txn_orphan_pf1")?.maxAge).toBe(0);
    expect(callbackRes.cookies.get("__txn_orphan_pf2")?.maxAge).toBe(0);
    // Tab B real login cookie must NOT be deleted
    const tabBCookie = callbackRes.cookies.get("__txn_tabB");
    expect(tabBCookie?.maxAge).not.toBe(0);

    // Session cookie written
    expect(callbackRes.cookies.get("__session")?.value).toBeTruthy();
  });
});
