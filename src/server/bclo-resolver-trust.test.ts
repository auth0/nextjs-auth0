import { NextRequest } from "next/server.js";
import * as jose from "jose";
import { describe, expect, it, vi } from "vitest";

import { BackchannelLogoutError } from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { createSizeLimitedFetch } from "../utils/fetchUtils.js";
import { AuthClientProvider } from "./auth-client-provider.js";
import { AuthClient } from "./auth-client.js";
import { DiscoveryCache } from "./discovery-cache.js";
import { StatefulSessionStore } from "./session/stateful-session-store.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

describe("BCLO Resolver-Based Trust", () => {
  const DEFAULT = {
    domain: "guabu.us.auth0.com",
    clientId: "client_123",
    clientSecret: "client-secret",
    appBaseUrl: "https://example.com",
    sid: "auth0-sid",
    sub: "user_123",
    alg: "RS256" as const
  };

  let keyPair: jose.GenerateKeyPairResult;

  // Generate key pair synchronously at module level
  const keyPairPromise = jose.generateKeyPair("RS256");

  async function getKeyPair() {
    if (!keyPair) {
      keyPair = await keyPairPromise;
    }
    return keyPair;
  }

  function getMockFetch(kp: jose.GenerateKeyPairResult) {
    return vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = new URL(
        input instanceof Request ? input.url : input.toString()
      );

      if (url.pathname === "/.well-known/openid-configuration") {
        return new Response(
          JSON.stringify({
            issuer: `https://${DEFAULT.domain}/`,
            authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
            token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
            jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
            end_session_endpoint: `https://${DEFAULT.domain}/oidc/logout`
          })
        );
      }

      if (url.pathname === "/.well-known/jwks.json") {
        const publicJwk = await jose.exportJWK(kp.publicKey);
        return new Response(JSON.stringify({ keys: [publicJwk] }));
      }

      return new Response("Not found", { status: 404 });
    });
  }

  async function generateLogoutToken({
    claims = {},
    audience = DEFAULT.clientId,
    issuer = `https://${DEFAULT.domain}/`,
    alg = DEFAULT.alg,
    privateKey
  }: {
    claims?: Record<string, unknown>;
    audience?: string;
    issuer?: string;
    alg?: string;
    privateKey?: CryptoKey;
  } = {}): Promise<string> {
    const kp = await getKeyPair();
    return await new jose.SignJWT({
      events: {
        "http://schemas.openid.net/event/backchannel-logout": {}
      },
      sub: DEFAULT.sub,
      sid: DEFAULT.sid,
      ...claims
    })
      .setProtectedHeader({ alg, typ: "logout+jwt" })
      .setIssuedAt()
      .setIssuer(issuer)
      .setAudience(audience)
      .setExpirationTime("2h")
      .setJti("some-jti")
      .sign(privateKey ?? kp.privateKey);
  }

  async function getDiscoveryCacheWithJWKS(): Promise<DiscoveryCache> {
    const kp = await getKeyPair();
    const cache = new DiscoveryCache();
    const jwksUri = `https://${DEFAULT.domain}/.well-known/jwks.json`;
    const entry = cache.getJwksCacheForUri(jwksUri);
    const publicJwk = await jose.exportJWK(kp.publicKey);
    Object.assign(entry, {
      jwks: { keys: [publicJwk] },
      uat: Date.now() - 1000 * 60
    });
    return cache;
  }

  async function createAuthClientWithStore(
    domain: string = DEFAULT.domain,
    opts: { discoveryCache?: DiscoveryCache } = {}
  ) {
    const kp = await getKeyPair();
    const secret = await generateSecret(32);
    const deleteByLogoutTokenSpy = vi.fn();
    const transactionStore = new TransactionStore({ secret });
    const sessionStore = new StatefulSessionStore({
      secret,
      store: {
        get: vi.fn(),
        set: vi.fn(),
        delete: vi.fn(),
        deleteByLogoutToken: deleteByLogoutTokenSpy
      }
    });
    const authClient = new AuthClient({
      transactionStore,
      sessionStore,
      domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      secret,
      appBaseUrl: DEFAULT.appBaseUrl,
      routes: getDefaultRoutes(),
      fetch: getMockFetch(kp),
      discoveryCache: opts.discoveryCache ?? (await getDiscoveryCacheWithJWKS())
    });
    return { authClient, deleteByLogoutTokenSpy, secret, sessionStore };
  }

  function makeBcloRequest(logoutToken: string, host?: string): NextRequest {
    const url = new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl);
    const req = new NextRequest(url, {
      method: "POST",
      body: new URLSearchParams({ logout_token: logoutToken }),
      headers: host ? { host } : undefined
    });
    return req;
  }

  // ===== Static Mode Tests =====

  describe("Static mode", () => {
    it("returns 204 when iss matches static domain", async () => {
      const { authClient, deleteByLogoutTokenSpy } =
        await createAuthClientWithStore();
      const token = await generateLogoutToken();
      const req = makeBcloRequest(token);

      const response = await authClient.handleBackChannelLogout(req);
      expect(response.status).toEqual(204);
      expect(deleteByLogoutTokenSpy).toHaveBeenCalledWith({
        sub: DEFAULT.sub,
        sid: DEFAULT.sid,
        iss: `https://${DEFAULT.domain}/`
      });
    });

    it("returns 403 when iss mismatches static domain (Gap 2 defense-in-depth)", async () => {
      const { authClient } = await createAuthClientWithStore();
      // Token with different issuer
      const token = await generateLogoutToken({
        issuer: "https://attacker.example.com/"
      });
      const req = makeBcloRequest(token);

      const response = await authClient.handleBackChannelLogout(req);
      expect(response.status).toEqual(403);
      expect(await response.text()).toContain(
        "Logout token issuer does not match the configured domain"
      );
    });

    it("skips iss pre-check when iss not normalizable (backward compatibility)", async () => {
      const { authClient } = await createAuthClientWithStore();
      // Token with non-normalizable iss (localhost) — extractIssuerDomainFromToken returns null
      // Pre-check should be skipped, then verifyLogoutToken will reject (iss mismatch)
      const kp = await getKeyPair();
      const token = await new jose.SignJWT({
        events: {
          "http://schemas.openid.net/event/backchannel-logout": {}
        },
        sub: DEFAULT.sub,
        sid: DEFAULT.sid
      })
        .setProtectedHeader({ alg: "RS256", typ: "logout+jwt" })
        .setIssuedAt()
        .setIssuer("http://localhost/") // tryNormalizeDomain returns null for localhost
        .setAudience(DEFAULT.clientId)
        .setExpirationTime("2h")
        .setJti("some-jti")
        .sign(kp.privateKey);

      const req = makeBcloRequest(token);

      // The pre-check is skipped (issuerDomain is null), so no 403 from our code.
      // verifyLogoutToken then throws JWTClaimValidationFailed (iss mismatch) which
      // is NOT caught in static mode — this propagates as an unhandled error.
      // This matches existing behavior: non-normalizable issuers were never handled
      // by the pre-check (backward compatibility).
      await expect(authClient.handleBackChannelLogout(req)).rejects.toThrow(
        'unexpected "iss" claim value'
      );
    });
  });

  // ===== Resolver Mode Tests =====

  describe("Resolver mode", () => {
    it("returns 204 when iss matches resolved domain", async () => {
      const { authClient, deleteByLogoutTokenSpy } =
        await createAuthClientWithStore();

      // Create a provider that resolves to the same domain
      const provider = new AuthClientProvider({
        domain: () => DEFAULT.domain,
        createAuthClient: () => authClient
      });
      authClient.provider = provider;

      const token = await generateLogoutToken();
      const req = makeBcloRequest(token);

      const response = await authClient.handleBackChannelLogout(req);
      expect(response.status).toEqual(204);
      expect(deleteByLogoutTokenSpy).toHaveBeenCalledWith({
        sub: DEFAULT.sub,
        sid: DEFAULT.sid,
        iss: `https://${DEFAULT.domain}/`
      });
    });

    it("returns 403 when iss mismatches resolved domain", async () => {
      const kp = await getKeyPair();
      const secret = await generateSecret(32);
      const deleteByLogoutTokenSpy = vi.fn();
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatefulSessionStore({
        secret,
        store: {
          get: vi.fn(),
          set: vi.fn(),
          delete: vi.fn(),
          deleteByLogoutToken: deleteByLogoutTokenSpy
        }
      });

      // Create authClient for a different domain than the token's iss
      const differentDomain = "different.auth0.com";
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: differentDomain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        fetch: getMockFetch(kp),
        discoveryCache: await getDiscoveryCacheWithJWKS()
      });

      // Provider resolves to a different domain than the token's iss
      const provider = new AuthClientProvider({
        domain: () => differentDomain,
        createAuthClient: () => authClient
      });
      authClient.provider = provider;

      const token = await generateLogoutToken(); // iss = guabu.us.auth0.com
      const req = makeBcloRequest(token);

      const response = await authClient.handleBackChannelLogout(req);
      expect(response.status).toEqual(403);
      expect(await response.text()).toContain(
        "Logout token issuer does not match the resolved domain"
      );
    });

    it("returns 400 when iss missing from token", async () => {
      const { authClient } = await createAuthClientWithStore();

      const provider = new AuthClientProvider({
        domain: () => DEFAULT.domain,
        createAuthClient: () => authClient
      });
      authClient.provider = provider;

      // Create token without proper iss (use IP which fails normalization)
      const kp = await getKeyPair();
      const token = await new jose.SignJWT({
        events: {
          "http://schemas.openid.net/event/backchannel-logout": {}
        },
        sub: DEFAULT.sub,
        sid: DEFAULT.sid
      })
        .setProtectedHeader({ alg: "RS256", typ: "logout+jwt" })
        .setIssuedAt()
        .setIssuer("http://192.168.1.1/") // IP address fails normalization
        .setAudience(DEFAULT.clientId)
        .setExpirationTime("2h")
        .setJti("some-jti")
        .sign(kp.privateKey);

      const req = makeBcloRequest(token);
      const response = await authClient.handleBackChannelLogout(req);
      expect(response.status).toEqual(400);
      expect(await response.text()).toContain("Missing 'iss' claim");
    });

    it("deleteByLogoutToken receives iss field", async () => {
      const { authClient, deleteByLogoutTokenSpy } =
        await createAuthClientWithStore();

      const provider = new AuthClientProvider({
        domain: () => DEFAULT.domain,
        createAuthClient: () => authClient
      });
      authClient.provider = provider;

      const token = await generateLogoutToken();
      const req = makeBcloRequest(token);

      await authClient.handleBackChannelLogout(req);
      expect(deleteByLogoutTokenSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          iss: `https://${DEFAULT.domain}/`
        })
      );
    });
  });

  // ===== Shared / Error Tests =====

  describe("Shared error handling", () => {
    it("returns 400 when logout_token missing from body", async () => {
      const { authClient } = await createAuthClientWithStore();
      const req = new NextRequest(
        new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: new URLSearchParams({}) // no logout_token
        }
      );

      const response = await authClient.handleBackChannelLogout(req);
      expect(response.status).toEqual(400);
      expect(await response.text()).toContain("Missing `logout_token`");
    });

    it("returns 500 when session store not configured", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const kp = await getKeyPair();
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        fetch: getMockFetch(kp)
      });

      const token = await generateLogoutToken();
      const req = makeBcloRequest(token);
      const response = await authClient.handleBackChannelLogout(req);
      expect(response.status).toEqual(500);
    });

    it("returns 500 when deleteByLogoutToken not implemented", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatefulSessionStore({
        secret,
        store: {
          get: vi.fn(),
          set: vi.fn(),
          delete: vi.fn()
          // no deleteByLogoutToken
        }
      });
      const kp = await getKeyPair();
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        fetch: getMockFetch(kp)
      });

      const token = await generateLogoutToken();
      const req = makeBcloRequest(token);
      const response = await authClient.handleBackChannelLogout(req);
      expect(response.status).toEqual(500);
    });
  });

  // ===== BackchannelLogoutError Tests =====

  describe("BackchannelLogoutError", () => {
    it("uses default code and custom message", () => {
      const error = new BackchannelLogoutError("custom message");
      expect(error.code).toEqual("backchannel_logout_error");
      expect(error.message).toEqual("custom message");
      expect(error.name).toEqual("BackchannelLogoutError");
    });

    it("uses default message when none provided", () => {
      const error = new BackchannelLogoutError();
      expect(error.code).toEqual("backchannel_logout_error");
      expect(error.message).toContain("backchannel logout request");
      expect(error.name).toEqual("BackchannelLogoutError");
    });
  });

  // ===== Response Body Size Limit Tests (kept from original) =====

  describe("Response Body Size Limit", () => {
    const maxBodySize = AuthClient.MAX_RESPONSE_BODY_SIZE;

    it("rejects responses with Content-Length exceeding limit", async () => {
      const oversizedLength = maxBodySize + 1;
      const mockFetch = vi.fn().mockResolvedValue(
        new Response("x", {
          headers: { "content-length": String(oversizedLength) }
        })
      );

      const wrappedFetch = createSizeLimitedFetch(mockFetch, maxBodySize);
      await expect(wrappedFetch("https://example.com")).rejects.toThrow(
        /Response body too large/
      );
    });

    it("allows responses within size limit", async () => {
      const body = "small response";
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(body, {
          headers: { "content-length": String(body.length) }
        })
      );

      const wrappedFetch = createSizeLimitedFetch(mockFetch, maxBodySize);
      const response = await wrappedFetch("https://example.com");
      expect(response.status).toEqual(200);
      expect(await response.text()).toEqual(body);
    });

    it("rejects chunked responses exceeding limit during streaming", async () => {
      const oversizedBody = "x".repeat(maxBodySize + 1);
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(oversizedBody) // No content-length header
      );

      const wrappedFetch = createSizeLimitedFetch(mockFetch, maxBodySize);
      const response = await wrappedFetch("https://example.com");
      await expect(response.text()).rejects.toThrow(/Response body too large/);
    });
  });
});
