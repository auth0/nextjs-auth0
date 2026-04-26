/**
 * mTLS Flow Tests (SDK-8638)
 *
 * Black-box tests that verify the end-to-end mTLS behaviour using MSW to
 * intercept HTTP requests at the network layer. The SDK is called normally
 * (no internal mocking); only outbound HTTP is stubbed.
 *
 * Key assertions:
 *   1. Token requests are routed to the mTLS alias endpoint
 *      (`mtls_endpoint_aliases.token_endpoint`) when `useMtls=true`.
 *   2. The custom fetch implementation is invoked for every request,
 *      confirming the TLS-aware transport is used end-to-end.
 *   3. The `client_secret` field is absent from the token request body —
 *      TLS client authentication only needs `client_id`.
 *   4. With `useMtls=false` (default), the standard token endpoint is used.
 */

import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import * as oauth from "oauth4webapi";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getDefaultRoutes, setupMswLifecycle } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import type { SessionData } from "../types/index.js";
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const DOMAIN = "auth0.local";
const CLIENT_ID = "test-client-id";
const APP_BASE_URL = "https://example.com";
const ALG = "RS256";

const STANDARD_TOKEN_ENDPOINT = `https://${DOMAIN}/oauth/token`;
const MTLS_TOKEN_ENDPOINT = `https://mtls.${DOMAIN}/oauth/token`;

// ---------------------------------------------------------------------------
// Discovery metadata (with and without mTLS aliases)
// ---------------------------------------------------------------------------

function makeDiscoveryMetadata(includeMtlsAliases: boolean) {
  const base = {
    issuer: `https://${DOMAIN}/`,
    authorization_endpoint: `https://${DOMAIN}/authorize`,
    token_endpoint: STANDARD_TOKEN_ENDPOINT,
    userinfo_endpoint: `https://${DOMAIN}/userinfo`,
    jwks_uri: `https://${DOMAIN}/.well-known/jwks.json`,
    end_session_endpoint: `https://${DOMAIN}/oidc/logout`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: [ALG]
  };

  if (!includeMtlsAliases) return base;

  return {
    ...base,
    mtls_endpoint_aliases: {
      token_endpoint: MTLS_TOKEN_ENDPOINT,
      userinfo_endpoint: `https://mtls.${DOMAIN}/userinfo`
    }
  };
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

let keyPair: jose.GenerateKeyPairResult;

async function makeIdToken(sub: string): Promise<string> {
  return new jose.SignJWT({ sub, iss: `https://${DOMAIN}/`, aud: CLIENT_ID })
    .setProtectedHeader({ alg: ALG })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(keyPair.privateKey);
}

// ---------------------------------------------------------------------------
// MSW server
// ---------------------------------------------------------------------------

const server = setupServer();
setupMswLifecycle(server);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function setupHandlers(
  {
    includeMtlsAliases,
    onTokenRequest
  }: {
    includeMtlsAliases: boolean;
    onTokenRequest?: (url: string, body: URLSearchParams) => void;
  } = { includeMtlsAliases: true }
) {
  const metadata = makeDiscoveryMetadata(includeMtlsAliases);

  const tokenHandler = async ({
    request
  }: {
    request: Request;
  }): Promise<Response> => {
    const body = new URLSearchParams(await request.text());
    onTokenRequest?.(request.url, body);

    const idToken = await makeIdToken("user-123");
    return HttpResponse.json({
      access_token: "at_new",
      refresh_token: "rt_new",
      id_token: idToken,
      token_type: "Bearer",
      expires_in: 86400
    } as oauth.TokenEndpointResponse);
  };

  server.use(
    http.get(`https://${DOMAIN}/.well-known/openid-configuration`, () =>
      HttpResponse.json(metadata)
    ),
    http.get(`https://${DOMAIN}/.well-known/jwks.json`, async () => {
      const jwk = await jose.exportJWK(keyPair.publicKey);
      return HttpResponse.json({
        keys: [{ ...jwk, kid: "test-key", use: "sig" }]
      });
    }),
    // Standard token endpoint (should NOT be called when useMtls=true)
    http.post(STANDARD_TOKEN_ENDPOINT, tokenHandler),
    // mTLS alias endpoint (should be called when useMtls=true)
    http.post(MTLS_TOKEN_ENDPOINT, tokenHandler)
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("mTLS flow tests", () => {
  let secret: string;

  beforeEach(async () => {
    if (!keyPair) {
      keyPair = await jose.generateKeyPair(ALG);
    }
    secret = await generateSecret(32);
  });

  function makeStores() {
    const transactionStore = new TransactionStore({ secret });
    const sessionStore = new StatelessSessionStore({ secret });
    return { transactionStore, sessionStore };
  }

  async function makeExpiredSession(): Promise<SessionData> {
    return {
      user: { sub: "user-123" },
      tokenSet: {
        accessToken: "at_old",
        refreshToken: "rt_old",
        expiresAt: Math.floor(Date.now() / 1000) - 3600 // expired 1 hour ago
      },
      internal: {
        sid: "test-sid",
        createdAt: Math.floor(Date.now() / 1000) - 7200
      }
    };
  }

  // -------------------------------------------------------------------------
  // 1. mTLS alias routing
  // -------------------------------------------------------------------------

  describe("token endpoint routing", () => {
    it("uses the mTLS alias endpoint when useMtls=true", async () => {
      const requestedUrls: string[] = [];
      setupHandlers({
        includeMtlsAliases: true,
        onTokenRequest: (url) => requestedUrls.push(url)
      });

      const { transactionStore, sessionStore } = makeStores();

      // Track which URLs the custom fetch is called with
      const customFetch = vi.fn(
        async (input: RequestInfo | URL, init?: RequestInit) => {
          return fetch(input, init);
        }
      );

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        appBaseUrl: APP_BASE_URL,
        secret,
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: customFetch as typeof fetch
      });

      const session = await makeExpiredSession();
      const [error] = await authClient.getTokenSet(session, {});

      expect(error).toBeNull();
      // The MSW handler for the mTLS endpoint should have been hit
      expect(requestedUrls).toContain(MTLS_TOKEN_ENDPOINT);
      // The standard endpoint should NOT have been called
      expect(requestedUrls).not.toContain(STANDARD_TOKEN_ENDPOINT);
    });

    it("uses the standard token endpoint when useMtls=false (default)", async () => {
      const requestedUrls: string[] = [];
      setupHandlers({
        includeMtlsAliases: true,
        onTokenRequest: (url) => requestedUrls.push(url)
      });

      const { transactionStore, sessionStore } = makeStores();

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        clientSecret: "client-secret",
        appBaseUrl: APP_BASE_URL,
        secret,
        routes: getDefaultRoutes()
        // useMtls defaults to false
      });

      const session = await makeExpiredSession();
      const [error] = await authClient.getTokenSet(session, {});

      expect(error).toBeNull();
      expect(requestedUrls).toContain(STANDARD_TOKEN_ENDPOINT);
      expect(requestedUrls).not.toContain(MTLS_TOKEN_ENDPOINT);
    });
  });

  // -------------------------------------------------------------------------
  // 2. No client_secret in token request body
  // -------------------------------------------------------------------------

  describe("client authentication", () => {
    it("does not include client_secret in the token request body when useMtls=true", async () => {
      let capturedBody: URLSearchParams | undefined;
      setupHandlers({
        includeMtlsAliases: true,
        onTokenRequest: (_, body) => {
          capturedBody = body;
        }
      });

      const { transactionStore, sessionStore } = makeStores();

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        appBaseUrl: APP_BASE_URL,
        secret,
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: fetch as typeof fetch
      });

      const session = await makeExpiredSession();
      await authClient.getTokenSet(session, {});

      expect(capturedBody).toBeDefined();
      // TLS client auth: only client_id should be present, never client_secret
      expect(capturedBody!.has("client_id")).toBe(true);
      expect(capturedBody!.has("client_secret")).toBe(false);
    });

    it("includes client_secret in the token request body when useMtls=false", async () => {
      let capturedBody: URLSearchParams | undefined;
      setupHandlers({
        includeMtlsAliases: true,
        onTokenRequest: (_, body) => {
          capturedBody = body;
        }
      });

      const { transactionStore, sessionStore } = makeStores();

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        clientSecret: "my-secret",
        appBaseUrl: APP_BASE_URL,
        secret,
        routes: getDefaultRoutes()
      });

      const session = await makeExpiredSession();
      await authClient.getTokenSet(session, {});

      expect(capturedBody).toBeDefined();
      expect(capturedBody!.has("client_secret")).toBe(true);
      expect(capturedBody!.get("client_secret")).toBe("my-secret");
    });
  });

  // -------------------------------------------------------------------------
  // 3. Custom fetch is invoked
  // -------------------------------------------------------------------------

  describe("custom fetch injection", () => {
    it("calls the custom fetch implementation for all Auth0 requests when useMtls=true", async () => {
      setupHandlers({ includeMtlsAliases: true });

      const { transactionStore, sessionStore } = makeStores();

      const customFetch = vi.fn(
        async (input: RequestInfo | URL, init?: RequestInit) =>
          fetch(input, init)
      );

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        appBaseUrl: APP_BASE_URL,
        secret,
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: customFetch as typeof fetch
      });

      const session = await makeExpiredSession();
      await authClient.getTokenSet(session, {});

      // customFetch must have been called at least once (discovery + token)
      expect(customFetch).toHaveBeenCalled();

      // All calls should be to Auth0 endpoints
      for (const [input] of customFetch.mock.calls) {
        const url =
          typeof input === "string"
            ? input
            : input instanceof URL
              ? input.toString()
              : (input as Request).url;
        expect(url).toMatch(new RegExp(`^https://(mtls\\.)?${DOMAIN}/`));
      }
    });
  });

  // -------------------------------------------------------------------------
  // 4. Graceful fallback when no mtls_endpoint_aliases in discovery
  // -------------------------------------------------------------------------

  describe("missing mtls_endpoint_aliases", () => {
    it("falls back to the standard token endpoint if discovery has no mtls_endpoint_aliases", async () => {
      const requestedUrls: string[] = [];
      setupHandlers({
        includeMtlsAliases: false,
        onTokenRequest: (url) => requestedUrls.push(url)
      });

      const { transactionStore, sessionStore } = makeStores();

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        appBaseUrl: APP_BASE_URL,
        secret,
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: fetch as typeof fetch
      });

      const session = await makeExpiredSession();
      const [error] = await authClient.getTokenSet(session, {});

      // Should not throw — just falls back to the standard endpoint
      expect(error).toBeNull();
      expect(requestedUrls).toContain(STANDARD_TOKEN_ENDPOINT);
    });
  });
});
