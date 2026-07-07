/**
 * Coverage for:
 * 1. getConnectionTokenSet — no-refresh-token error, happy exchange path, FAILED_TO_EXCHANGE error, cached-and-valid passthrough
 * 2. withMtlsEndpoint — swaps token_endpoint to mtls_endpoint_aliases.token_endpoint when useMtls=true
 * 3. MtlsError construction-time guards — MTLS_REQUIRES_CUSTOM_FETCH, MTLS_INCOMPATIBLE_CLIENT_AUTH
 */

import * as jose from "jose";
import { describe, expect, it, vi } from "vitest";

import {
  AccessTokenForConnectionErrorCode,
  MtlsError,
  MtlsErrorCode
} from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// ---------------------------------------------------------------------------
// Shared test infrastructure
// ---------------------------------------------------------------------------

const DOMAIN = "guabu.us.auth0.com";
const CLIENT_ID = "client_123";
const CLIENT_SECRET = "client-secret";
const APP_BASE_URL = "https://example.com";

const _authorizationServerMetadata = {
  issuer: `https://${DOMAIN}/`,
  authorization_endpoint: `https://${DOMAIN}/authorize`,
  token_endpoint: `https://${DOMAIN}/oauth/token`,
  userinfo_endpoint: `https://${DOMAIN}/userinfo`,
  jwks_uri: `https://${DOMAIN}/.well-known/jwks.json`,
  registration_endpoint: `https://${DOMAIN}/oidc/register`,
  revocation_endpoint: `https://${DOMAIN}/oauth/revoke`,
  scopes_supported: ["openid", "profile", "offline_access"],
  response_types_supported: ["code"],
  code_challenge_methods_supported: ["S256"],
  subject_types_supported: ["public"],
  token_endpoint_auth_methods_supported: ["client_secret_basic"],
  claims_supported: ["aud", "exp", "iat", "iss", "sub"],
  request_uri_parameter_supported: false,
  request_parameter_supported: false,
  id_token_signing_alg_values_supported: ["RS256"],
  token_endpoint_auth_signing_alg_values_supported: ["RS256"],
  backchannel_logout_supported: true,
  backchannel_logout_session_supported: true,
  end_session_endpoint: `https://${DOMAIN}/oidc/logout`,
  pushed_authorization_request_endpoint: `https://${DOMAIN}/oauth/par`,
  backchannel_authentication_endpoint: `https://${DOMAIN}/bc-authorize`,
  backchannel_token_delivery_modes_supported: ["poll"]
};

function makeMinimalFetch(
  overrides?: (url: URL, init?: RequestInit) => Response | null
) {
  return vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url =
        input instanceof Request
          ? new URL(input.url)
          : new URL(input as string);
      if (overrides) {
        const r = overrides(url, init);
        if (r !== null) return r;
      }
      if (url.pathname === "/.well-known/openid-configuration") {
        return Response.json(_authorizationServerMetadata);
      }
      if (url.pathname === "/.well-known/jwks.json") {
        const kp = await jose.generateKeyPair("RS256");
        const pub = await jose.exportJWK(kp.publicKey);
        return Response.json({ keys: [pub] });
      }
      return new Response(null, { status: 404 });
    }
  );
}

async function makeAuthClient(
  secret: string,
  fetchMock: ReturnType<typeof vi.fn>,
  extra: Record<string, unknown> = {}
) {
  return new AuthClient({
    transactionStore: new TransactionStore({ secret }),
    sessionStore: new StatelessSessionStore({ secret }),
    domain: DOMAIN,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    secret,
    appBaseUrl: APP_BASE_URL,
    routes: getDefaultRoutes(),
    fetch: fetchMock,
    ...extra
  });
}

// ---------------------------------------------------------------------------
// 1. getConnectionTokenSet
// ---------------------------------------------------------------------------

describe("getConnectionTokenSet — no refresh token + expired cache → MISSING_REFRESH_TOKEN", () => {
  it("returns MISSING_REFRESH_TOKEN when no refreshToken and connectionTokenSet is expired", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    const tokenSet = {
      accessToken: "at_123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600
      // no refreshToken
    };

    const expiredConnectionTokenSet = {
      accessToken: "old_conn_at",
      expiresAt: Math.floor(Date.now() / 1000) - 60, // expired
      connection: "google-oauth2"
    };

    const [err, result] = await (authClient as any).getConnectionTokenSet(
      tokenSet,
      expiredConnectionTokenSet,
      { connection: "google-oauth2" }
    );

    expect(err).toBeDefined();
    expect(err.code).toBe(
      AccessTokenForConnectionErrorCode.MISSING_REFRESH_TOKEN
    );
    expect(result).toBeNull();
  });

  it("returns MISSING_REFRESH_TOKEN when no refreshToken and no cached connectionTokenSet", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    const tokenSet = {
      accessToken: "at_123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    };

    const [err, result] = await (authClient as any).getConnectionTokenSet(
      tokenSet,
      undefined,
      { connection: "google-oauth2" }
    );

    expect(err).toBeDefined();
    expect(err.code).toBe(
      AccessTokenForConnectionErrorCode.MISSING_REFRESH_TOKEN
    );
    expect(result).toBeNull();
  });
});

describe("getConnectionTokenSet — valid cached token → passthrough without exchange", () => {
  it("returns the cached connectionTokenSet when it is still valid", async () => {
    const secret = await generateSecret(32);
    const fetchMock = makeMinimalFetch();
    const authClient = await makeAuthClient(secret, fetchMock);

    const tokenSet = {
      accessToken: "at_123",
      refreshToken: "rt_123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    };

    const validCached = {
      accessToken: "cached_conn_at",
      expiresAt: Math.floor(Date.now() / 1000) + 3600, // not expired
      connection: "google-oauth2"
    };

    const [err, result] = await (authClient as any).getConnectionTokenSet(
      tokenSet,
      validCached,
      { connection: "google-oauth2" }
    );

    expect(err).toBeNull();
    expect(result).toBe(validCached);
    // Discovery should not be called — no token exchange needed
    const fetchCalls = fetchMock.mock.calls.map((c: any) => {
      const u = c[0] instanceof Request ? c[0].url : String(c[0]);
      return new URL(u).pathname;
    });
    expect(fetchCalls).not.toContain("/oauth/token");
  });
});

describe("getConnectionTokenSet — refresh token present + expired cache → exchanges for new token", () => {
  it("calls the token endpoint and returns a new ConnectionTokenSet", async () => {
    const secret = await generateSecret(32);

    const fetchMock = makeMinimalFetch((url) => {
      if (url.pathname === "/oauth/token") {
        return Response.json({
          access_token: "new_conn_at",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid"
        });
      }
      return null;
    });

    const authClient = await makeAuthClient(secret, fetchMock);

    const tokenSet = {
      accessToken: "at_123",
      refreshToken: "rt_123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    };

    const [err, result] = await (authClient as any).getConnectionTokenSet(
      tokenSet,
      undefined, // no cached token
      { connection: "google-oauth2" }
    );

    expect(err).toBeNull();
    expect(result).toBeDefined();
    expect(result.accessToken).toBe("new_conn_at");
    expect(result.connection).toBe("google-oauth2");
    expect(result.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("returns FAILED_TO_EXCHANGE when the token endpoint returns an error", async () => {
    const secret = await generateSecret(32);

    const fetchMock = makeMinimalFetch((url) => {
      if (url.pathname === "/oauth/token") {
        return Response.json(
          {
            error: "invalid_grant",
            error_description: "Refresh token expired."
          },
          { status: 400 }
        );
      }
      return null;
    });

    const authClient = await makeAuthClient(secret, fetchMock);

    const tokenSet = {
      accessToken: "at_123",
      refreshToken: "expired_rt",
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    };

    const [err, result] = await (authClient as any).getConnectionTokenSet(
      tokenSet,
      undefined,
      { connection: "google-oauth2" }
    );

    expect(err).toBeDefined();
    expect(err.code).toBe(AccessTokenForConnectionErrorCode.FAILED_TO_EXCHANGE);
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. withMtlsEndpoint — token endpoint swap when useMtls=true
// ---------------------------------------------------------------------------

describe("withMtlsEndpoint — mTLS token endpoint substitution", () => {
  it("routes the token exchange to mtls_endpoint_aliases.token_endpoint when useMtls=true", async () => {
    const secret = await generateSecret(32);
    const mtlsTokenEndpoint = `https://mtls.${DOMAIN}/oauth/token`;

    const capturedUrls: string[] = [];

    // Discovery returns mtls_endpoint_aliases; token endpoint should be swapped
    const fetchMock = vi.fn(
      async (
        input: RequestInfo | URL,
        _init?: RequestInit
      ): Promise<Response> => {
        const url =
          input instanceof Request
            ? new URL(input.url)
            : new URL(input as string);
        capturedUrls.push(url.href);

        if (url.pathname === "/.well-known/openid-configuration") {
          return Response.json({
            ..._authorizationServerMetadata,
            mtls_endpoint_aliases: {
              token_endpoint: mtlsTokenEndpoint
            }
          });
        }
        if (url.pathname === "/.well-known/jwks.json") {
          return Response.json({ keys: [] });
        }
        if (url.href === mtlsTokenEndpoint) {
          return Response.json({
            access_token: "mtls_conn_at",
            token_type: "Bearer",
            expires_in: 3600
          });
        }
        return new Response(null, { status: 404 });
      }
    );

    // useMtls is incompatible with clientSecret — construct without it
    const authClient = new AuthClient({
      transactionStore: new TransactionStore({ secret }),
      sessionStore: new StatelessSessionStore({ secret }),
      domain: DOMAIN,
      clientId: CLIENT_ID,
      // no clientSecret — mTLS replaces secret-based auth
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: fetchMock,
      useMtls: true
    });

    const tokenSet = {
      accessToken: "at_123",
      refreshToken: "rt_123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    };

    const [err, result] = await (authClient as any).getConnectionTokenSet(
      tokenSet,
      undefined,
      { connection: "google-oauth2" }
    );

    expect(err).toBeNull();
    expect(result?.accessToken).toBe("mtls_conn_at");
    // The token exchange must have gone to the mTLS endpoint, not the standard one
    expect(capturedUrls).toContain(mtlsTokenEndpoint);
    expect(capturedUrls).not.toContain(`https://${DOMAIN}/oauth/token`);
  });

  it("uses the standard token_endpoint when useMtls=false (no alias substitution)", async () => {
    const secret = await generateSecret(32);
    const capturedUrls: string[] = [];

    const fetchMock = vi.fn(
      async (
        input: RequestInfo | URL,
        _init?: RequestInit
      ): Promise<Response> => {
        const url =
          input instanceof Request
            ? new URL(input.url)
            : new URL(input as string);
        capturedUrls.push(url.href);

        if (url.pathname === "/.well-known/openid-configuration") {
          return Response.json({
            ..._authorizationServerMetadata,
            mtls_endpoint_aliases: {
              token_endpoint: `https://mtls.${DOMAIN}/oauth/token`
            }
          });
        }
        if (url.pathname === "/.well-known/jwks.json") {
          return Response.json({ keys: [] });
        }
        if (url.pathname === "/oauth/token") {
          return Response.json({
            access_token: "standard_conn_at",
            token_type: "Bearer",
            expires_in: 3600
          });
        }
        return new Response(null, { status: 404 });
      }
    );

    const authClient = await makeAuthClient(secret, fetchMock);
    // useMtls defaults to false

    const tokenSet = {
      accessToken: "at_123",
      refreshToken: "rt_123",
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    };

    const [err, result] = await (authClient as any).getConnectionTokenSet(
      tokenSet,
      undefined,
      { connection: "google-oauth2" }
    );

    expect(err).toBeNull();
    expect(result?.accessToken).toBe("standard_conn_at");
    expect(capturedUrls).toContain(`https://${DOMAIN}/oauth/token`);
    expect(capturedUrls).not.toContain(`https://mtls.${DOMAIN}/oauth/token`);
  });
});

// ---------------------------------------------------------------------------
// 3. MtlsError construction-time guards
// ---------------------------------------------------------------------------

describe("AuthClient constructor — mTLS validation errors", () => {
  it("throws MtlsError(MTLS_REQUIRES_CUSTOM_FETCH) when useMtls=true but no fetch provided", async () => {
    const secret = await generateSecret(32);

    // useMtls=true with no fetch — must throw before construction completes
    const makeNoFetch = () =>
      new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore: new StatelessSessionStore({ secret }),
        domain: DOMAIN,
        clientId: CLIENT_ID,
        // no clientSecret — mTLS replaces secret-based auth
        secret,
        appBaseUrl: APP_BASE_URL,
        routes: getDefaultRoutes(),
        useMtls: true
        // fetch intentionally omitted
      });

    expect(makeNoFetch).toThrow(MtlsError);
    // Verify the specific error code via the thrown instance
    let thrown: any;
    try {
      makeNoFetch();
    } catch (e) {
      thrown = e;
    }
    expect(thrown.code).toBe(MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH);
  });

  it("throws MtlsError(MTLS_INCOMPATIBLE_CLIENT_AUTH) when useMtls=true combined with clientSecret", async () => {
    const secret = await generateSecret(32);

    // useMtls + clientSecret is incompatible — must throw at construction
    const makeIncompat = () =>
      new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore: new StatelessSessionStore({ secret }),
        domain: DOMAIN,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET, // incompatible with mTLS
        secret,
        appBaseUrl: APP_BASE_URL,
        routes: getDefaultRoutes(),
        fetch: vi.fn(),
        useMtls: true
      });

    expect(makeIncompat).toThrow(MtlsError);
    let thrown: any;
    try {
      makeIncompat();
    } catch (e) {
      thrown = e;
    }
    expect(thrown.code).toBe(MtlsErrorCode.MTLS_INCOMPATIBLE_CLIENT_AUTH);
  });
});
