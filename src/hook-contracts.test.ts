import { NextRequest, NextResponse } from "next/server.js";
import { describe, expect, it } from "vitest";

import { AuthClient } from "./server/auth-client.js";
import { encrypt } from "./server/cookies.js";
import { StatelessSessionStore } from "./server/session/stateless-session-store.js";
import { TransactionStore } from "./server/transaction-store.js";
import { getDefaultRoutes } from "./test/defaults.js";
import { generateSecret } from "./test/utils.js";
import { RESPONSE_TYPES } from "./types/index.js";

const DOMAIN = "test.auth0.com";
const APP_BASE_URL = "https://example.com";

function makeDiscoveryResponse() {
  return new Response(
    JSON.stringify({
      issuer: `https://${DOMAIN}/`,
      authorization_endpoint: `https://${DOMAIN}/authorize`,
      token_endpoint: `https://${DOMAIN}/oauth/token`,
      jwks_uri: `https://${DOMAIN}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"]
    })
  );
}

async function makeTransactionCookie(secret: string, state: string) {
  const txn = {
    state,
    returnTo: "/dashboard",
    responseType: RESPONSE_TYPES.CODE,
    codeVerifier: "cv_abc"
  };
  const expiry = Math.floor(Date.now() / 1000) + 3600;
  return encrypt(txn, secret, expiry);
}

describe("onCallback hook contract", () => {
  it("onCallback throwing propagates to the caller (not swallowed by the SDK)", async () => {
    const secret = await generateSecret(32);

    const authClient = new AuthClient({
      transactionStore: new TransactionStore({ secret }),
      sessionStore: new StatelessSessionStore({ secret }),
      domain: DOMAIN,
      clientId: "client_id",
      clientSecret: "client_secret",
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: () => Promise.resolve(makeDiscoveryResponse()),
      onCallback: async () => {
        throw new Error("onCallback deliberately threw");
      }
    });

    const state = "test-state-123";
    const txnCookie = await makeTransactionCookie(secret, state);

    const headers = new Headers({
      cookie: `__txn_${state}=${txnCookie}`
    });

    const req = new NextRequest(
      new URL(`/auth/callback?code=auth_code&state=${state}`, APP_BASE_URL),
      { method: "GET", headers }
    );

    await expect(authClient.handleCallback(req)).rejects.toThrow(
      "onCallback deliberately threw"
    );
  });

  it("onCallback is called with the error when an error occurs (error is not silently swallowed)", async () => {
    const secret = await generateSecret(32);
    const capturedErrors: Error[] = [];

    const authClient = new AuthClient({
      transactionStore: new TransactionStore({ secret }),
      sessionStore: new StatelessSessionStore({ secret }),
      domain: DOMAIN,
      clientId: "client_id",
      clientSecret: "client_secret",
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: () => Promise.resolve(makeDiscoveryResponse()),
      onCallback: async (error) => {
        if (error) capturedErrors.push(error);
        return NextResponse.redirect(new URL("/", APP_BASE_URL));
      }
    });

    const req = new NextRequest(
      new URL("/auth/callback?state=missing-txn-state", APP_BASE_URL),
      { method: "GET" }
    );

    await authClient.handleCallback(req);
    expect(capturedErrors.length).toBeGreaterThan(0);
  });

  it("default onCallback (no hook provided) returns a redirect response on error", async () => {
    const secret = await generateSecret(32);

    const authClient = new AuthClient({
      transactionStore: new TransactionStore({ secret }),
      sessionStore: new StatelessSessionStore({ secret }),
      domain: DOMAIN,
      clientId: "client_id",
      clientSecret: "client_secret",
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: () => Promise.resolve(makeDiscoveryResponse())
    });

    const req = new NextRequest(
      new URL("/auth/callback?state=no-transaction", APP_BASE_URL),
      { method: "GET" }
    );

    const res = await authClient.handleCallback(req);
    expect(res).toBeInstanceOf(NextResponse);
    expect(res.status).not.toBe(200);
  });
});

describe("beforeSessionSaved hook contract", () => {
  it("beforeSessionSaved throwing propagates to the caller (not silently swallowed)", async () => {
    const secret = await generateSecret(32);

    const authClient = new AuthClient({
      transactionStore: new TransactionStore({ secret }),
      sessionStore: new StatelessSessionStore({ secret }),
      domain: DOMAIN,
      clientId: "client_id",
      clientSecret: "client_secret",
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: () => Promise.resolve(makeDiscoveryResponse()),
      beforeSessionSaved: async () => {
        throw new Error("beforeSessionSaved deliberately threw");
      }
    });

    const session = {
      user: { sub: "user_123" },
      tokenSet: { accessToken: "at_123", idToken: "idt_123" },
      internal: { sid: "sid_123", createdAt: Math.floor(Date.now() / 1000) }
    };

    await expect(
      (authClient as any).finalizeSession(session, "id_token_value")
    ).rejects.toThrow("beforeSessionSaved deliberately threw");
  });

  it("beforeSessionSaved receives the session and idToken, and its return value replaces the session user", async () => {
    const secret = await generateSecret(32);
    let receivedIdToken: string | null = null;

    const authClient = new AuthClient({
      transactionStore: new TransactionStore({ secret }),
      sessionStore: new StatelessSessionStore({ secret }),
      domain: DOMAIN,
      clientId: "client_id",
      clientSecret: "client_secret",
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: () => Promise.resolve(makeDiscoveryResponse()),
      beforeSessionSaved: async (session, idToken) => {
        receivedIdToken = idToken;
        return {
          ...session,
          user: { ...session.user, custom: "injected" }
        };
      }
    });

    const session = {
      user: { sub: "user_123" },
      tokenSet: { accessToken: "at_123" },
      internal: { sid: "sid_123", createdAt: Math.floor(Date.now() / 1000) }
    };

    const result = await (authClient as any).finalizeSession(
      session,
      "my_id_token"
    );

    expect(receivedIdToken).toBe("my_id_token");
    expect((result.user as any).custom).toBe("injected");
    expect(result.internal).toEqual(session.internal);
  });
});
