import { NextRequest } from "next/server.js";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import * as oauth from "oauth4webapi";
import { beforeAll, describe, expect, it } from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { RESPONSE_TYPES, TransactionState } from "../types/index.js";
import { generateDpopKeyPair } from "../utils/dpopUtils.js";
import { AuthClient } from "./auth-client.js";
import { decrypt, encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

/**
 * Real SDK Integration Test for DPoP Nonce Retry on Auth Code Callback
 *
 * This test validates that AuthClient.handleCallback() properly implements
 * RFC 9449 Section 8 behavior: when a token endpoint returns 400 with
 * use_dpop_nonce error and DPoP-Nonce header, the SDK automatically retries
 * the request with the nonce included in the DPoP proof.
 *
 * Test Flow:
 * 1. Create AuthClient with DPoP enabled
 * 2. Build callback request with authorization code and transaction cookie
 * 3. Call handleCallback() - the actual SDK method users call
 * 4. Custom fetch mock intercepts: first token request fails with use_dpop_nonce, second succeeds
 * 5. Validate handleCallback() returns successful response with session cookie
 * 6. This proves the retry wrapper is working transparently at the SDK level
 */

// Test constants
const DEFAULT = {
  domain: "auth0.local",
  clientId: "test_client_id",
  clientSecret: "test_client_secret",
  appBaseUrl: "https://example.com",
  sub: "user_123",
  sid: "auth0-session-id",
  alg: "RS256",
  accessToken: "access_token_123",
  refreshToken: "refresh_token_123",
  authorizationCode: "auth_code_123",
  nonce: "nonce_value_123"
};

let keyPair: jose.GenerateKeyPairResult;
let dpopKeyPair: Awaited<ReturnType<typeof generateDpopKeyPair>>;

/**
 * Helper to create a stateful DPoP nonce retry handler for MSW
 * Manages internal state tracking for request count and DPoP nonce validation
 * Returns 400 with use_dpop_nonce on first request, 200 with tokens on retry
 */
function createDPoPNonceRetryHandler(keyPairParam: jose.GenerateKeyPairResult) {
  // Internal state management for this handler instance
  const state = {
    requestCount: 0,
    requests: [] as Array<{
      attempt: number;
      hasDPoP: boolean;
      hasNonce: boolean;
      nonce?: string;
      dpopJwt?: string;
    }>
  };

  // Helper to parse DPoP JWT and extract nonce claim
  const extractDPoPNonce = (
    dpopHeader: string | null
  ): { hasNonce: boolean; nonce?: string } => {
    if (!dpopHeader || typeof dpopHeader !== "string") {
      return { hasNonce: false };
    }

    try {
      // DPoP is a JWT: header.payload.signature
      const parts = dpopHeader.split(".");
      if (parts.length === 3 && parts[1]) {
        const payload = JSON.parse(
          Buffer.from(parts[1], "base64url").toString("utf-8")
        );
        if ("nonce" in payload) {
          return { hasNonce: true, nonce: payload.nonce as string };
        }
      }
    } catch {
      // If parsing fails, assume no nonce
    }

    return { hasNonce: false };
  };

  // MSW handler that manages the retry flow
  const handler = async ({ request }: { request: Request }) => {
    state.requestCount++;

    // Extract DPoP header from request
    const dpopHeader = request.headers.get("dpop");
    const { hasNonce, nonce } = extractDPoPNonce(dpopHeader);

    // Track request details for assertions
    state.requests.push({
      attempt: state.requestCount,
      hasDPoP: !!dpopHeader,
      hasNonce,
      nonce,
      dpopJwt: dpopHeader || undefined
    });

    // First request: Return 400 with use_dpop_nonce error
    if (state.requestCount === 1) {
      return HttpResponse.json(
        {
          error: "use_dpop_nonce",
          error_description: "Authorization server requires nonce in DPoP proof"
        },
        {
          status: 400,
          headers: {
            "dpop-nonce": "server_nonce_value_123"
          }
        }
      );
    }

    // Second request: Return 200 with tokens
    const idToken = await new jose.SignJWT({
      sid: DEFAULT.sid,
      sub: DEFAULT.sub,
      nonce: DEFAULT.nonce,
      auth_time: Math.floor(Date.now() / 1000),
      iss: `https://${DEFAULT.domain}/`,
      aud: DEFAULT.clientId
    })
      .setProtectedHeader({ alg: DEFAULT.alg })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(keyPairParam.privateKey);

    return HttpResponse.json({
      access_token: DEFAULT.accessToken,
      refresh_token: DEFAULT.refreshToken,
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 86400
    } as oauth.TokenEndpointResponse);
  };

  return { handler, state };
}

beforeAll(async () => {
  keyPair = await jose.generateKeyPair("RS256");
  dpopKeyPair = await generateDpopKeyPair();
});

describe("AuthClient.handleCallback with DPoP Nonce Retry", () => {
  it("should transparently retry auth code exchange when server returns use_dpop_nonce error", async () => {
    // Create handler with internal state management
    const { handler: tokenHandler, state: tokenHandlerState } =
      createDPoPNonceRetryHandler(keyPair);

    // Setup MSW handlers
    const handlers = [
      http.get(
        `https://${DEFAULT.domain}/.well-known/openid-configuration`,
        () => {
          return HttpResponse.json({
            issuer: `https://${DEFAULT.domain}/`,
            token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
            jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`
          });
        }
      ),

      http.get(`https://${DEFAULT.domain}/.well-known/jwks.json`, async () => {
        const jwk = await jose.exportJWK(keyPair.publicKey);
        return HttpResponse.json({ keys: [jwk] });
      }),

      http.post(`https://${DEFAULT.domain}/oauth/token`, tokenHandler)
    ];

    const server = setupServer(...handlers);

    // Start MSW server for this test
    server.listen({ onUnhandledRequest: "error" });

    try {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });

      // Create AuthClient with DPoP enabled
      // Note: No custom fetch needed - MSW intercepts global fetch automatically
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        dpopKeyPair,
        useDPoP: true
      });

      // Build callback request
      const state = "test-state-123";
      const callbackUrl = new URL("/auth/callback", DEFAULT.appBaseUrl);
      callbackUrl.searchParams.set("code", DEFAULT.authorizationCode);
      callbackUrl.searchParams.set("state", state);

      // Create and encrypt transaction state
      const transactionState: TransactionState = {
        nonce: DEFAULT.nonce,
        maxAge: 3600,
        codeVerifier: "code_verifier_123",
        responseType: RESPONSE_TYPES.CODE,
        state,
        returnTo: "/dashboard"
      };

      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const encryptedTxn = await encrypt(transactionState, secret, expiration);

      const headers = new Headers();
      headers.set("cookie", `__txn_${state}=${encryptedTxn}`);

      const request = new NextRequest(callbackUrl, {
        method: "GET",
        headers
      });

      // CALL THE ACTUAL SDK METHOD
      // This is where withDPoPNonceRetry() is applied internally
      const response = await authClient.handleCallback(request);

      // Validate response
      expect(response.status).toBe(307); // Successful callback redirect

      // Validate redirect goes to returnTo
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();
      expect(new URL(location!, DEFAULT.appBaseUrl).pathname).toBe(
        "/dashboard"
      );

      // Validate session cookie was created with tokens
      const sessionCookie = response.cookies.get("__session");
      expect(sessionCookie).toBeDefined();

      const { payload: session } = (await decrypt(
        sessionCookie!.value,
        secret
      )) as jose.JWTDecryptResult;

      expect(session).toMatchObject({
        user: {
          sub: DEFAULT.sub
        },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          idToken: expect.stringMatching(/^eyJhbGciOiJSUzI1NiJ9\..+\..+$/)
        }
      });

      // Validate transaction cookie was cleaned up
      const txnCookie = response.cookies.get(`__txn_${state}`);
      expect(txnCookie).toBeDefined();
      expect(txnCookie!.value).toBe("");
      expect(txnCookie!.maxAge).toBe(0);

      // Validate that TWO fetch calls were made to token endpoint:
      // 1. First call: No nonce → Got 400 use_dpop_nonce error
      // 2. Second call: With nonce → Got 200 with tokens
      //
      // This proves handleCallback() used withDPoPNonceRetry() wrapper,
      // which detected the 400 error, extracted the nonce from DPoP-Nonce
      // header, and automatically retried with the nonce included.
      //
      // If the retry wrapper wasn't applied, we'd see:
      // - Only 1 token endpoint call (the failing one)
      // - handleCallback would propagate the 400 error to the user
      // - Test would fail at the response.status.toBe(307) assertion
      expect(tokenHandlerState.requestCount).toBe(2);

      // Verify DPoP headers were sent correctly
      expect(tokenHandlerState.requests).toHaveLength(2);

      // First request: DPoP WITHOUT nonce
      expect(tokenHandlerState.requests[0]).toMatchObject({
        attempt: 1,
        hasDPoP: true,
        hasNonce: false,
        nonce: undefined
      });

      // Second request: DPoP WITH nonce (the retry)
      // This is the critical validation - the client actually sent the nonce
      expect(tokenHandlerState.requests[1]).toMatchObject({
        attempt: 2,
        hasDPoP: true,
        hasNonce: true
      });

      // Verify the nonce value matches what server provided
      // This proves oauth4webapi DPoP handle correctly:
      // 1. Received the DPoP-Nonce header from the 400 error response
      // 2. Extracted the nonce value ("server_nonce_value_123")
      // 3. Injected it into the DPoP JWT payload on retry
      expect(tokenHandlerState.requests[1].nonce).toBe(
        "server_nonce_value_123"
      );

      // Additional validation: Decode the second request's DPoP JWT and verify
      // the payload contains the exact nonce claim
      const secondRequestDPoP = tokenHandlerState.requests[1].dpopJwt;
      expect(secondRequestDPoP).toBeDefined();

      if (secondRequestDPoP) {
        const dpoPPayload = jose.decodeJwt(secondRequestDPoP);
        expect(dpoPPayload.nonce).toBe("server_nonce_value_123");
        // Additional claims to verify DPoP structure
        expect(dpoPPayload.htm).toBe("POST");
        expect(dpoPPayload.htu).toMatch(/oauth\/token$/);
      }
    } finally {
      // Clean up MSW server
      server.close();
    }
  });
});
