import { NextRequest } from "next/server.js";
import * as oauth from "oauth4webapi";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { MtlsError, MtlsErrorCode } from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import type { SessionData } from "../types/index.js";
import { AuthClient } from "./auth-client.js";
import { encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

vi.mock("oauth4webapi", async () => {
  const actual = await vi.importActual<typeof oauth>("oauth4webapi");
  return {
    ...actual,
    TlsClientAuth: vi.fn(() => ({ type: "tls" })),
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    revocationRequest: vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 200 })),
    processRevocationResponse: vi.fn().mockResolvedValue(undefined),
    customFetch: Symbol("customFetch"),
    allowInsecureRequests: Symbol("allowInsecureRequests")
  };
});

const DOMAIN = "test.auth0.com";
const CLIENT_ID = "test-client-id";

function makeStores(secret: string) {
  return {
    transactionStore: new TransactionStore({ secret }),
    sessionStore: new StatelessSessionStore({ secret })
  };
}

function setupDiscoveryMocks(overrides: Record<string, unknown> = {}) {
  vi.mocked(oauth.discoveryRequest).mockResolvedValue(new Response());
  vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
    issuer: `https://${DOMAIN}/`,
    authorization_endpoint: `https://${DOMAIN}/authorize`,
    token_endpoint: `https://${DOMAIN}/oauth/token`,
    revocation_endpoint: `https://${DOMAIN}/oauth/revoke`,
    jwks_uri: `https://${DOMAIN}/.well-known/jwks.json`,
    mtls_endpoint_aliases: {
      token_endpoint: `https://mtls.${DOMAIN}/oauth/token`,
      revocation_endpoint: `https://mtls.${DOMAIN}/oauth/revoke`
    },
    ...overrides
  } as any);
}

describe("mTLS AuthClient", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
    vi.mocked(oauth.TlsClientAuth).mockClear();
    vi.mocked(oauth.revocationRequest).mockClear();
    vi.mocked(oauth.processRevocationResponse).mockClear();
    setupDiscoveryMocks();
  });

  describe("constructor validation", () => {
    it("throws MtlsError when useMtls=true and no custom fetch provided", async () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      expect(
        () =>
          new AuthClient({
            transactionStore,
            sessionStore,
            domain: DOMAIN,
            clientId: CLIENT_ID,
            // no clientSecret — avoid triggering MTLS_INCOMPATIBLE_CLIENT_AUTH first
            secret,
            appBaseUrl: "https://example.com",
            routes: getDefaultRoutes(),
            useMtls: true
            // intentionally no `fetch`
          })
      ).toThrow(MtlsError);
    });

    it("throws MtlsError with code MTLS_REQUIRES_CUSTOM_FETCH when fetch is missing", async () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      let caught: unknown;
      try {
        new AuthClient({
          transactionStore,
          sessionStore,
          domain: DOMAIN,
          clientId: CLIENT_ID,
          // no clientSecret
          secret,
          appBaseUrl: "https://example.com",
          routes: getDefaultRoutes(),
          useMtls: true
          // no fetch
        });
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeInstanceOf(MtlsError);
      expect((caught as MtlsError).code).toBe(
        MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH
      );
    });

    it("throws MtlsError with code MTLS_INCOMPATIBLE_CLIENT_AUTH when clientSecret is also set", () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      let caught: unknown;
      try {
        new AuthClient({
          transactionStore,
          sessionStore,
          domain: DOMAIN,
          clientId: CLIENT_ID,
          clientSecret: "should-not-be-here",
          secret,
          appBaseUrl: "https://example.com",
          routes: getDefaultRoutes(),
          useMtls: true,
          fetch: globalThis.fetch
        });
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeInstanceOf(MtlsError);
      expect((caught as MtlsError).code).toBe(
        MtlsErrorCode.MTLS_INCOMPATIBLE_CLIENT_AUTH
      );
    });

    it("throws MtlsError with code MTLS_INCOMPATIBLE_CLIENT_AUTH when clientAssertionSigningKey is also set", () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      let caught: unknown;
      try {
        new AuthClient({
          transactionStore,
          sessionStore,
          domain: DOMAIN,
          clientId: CLIENT_ID,
          clientAssertionSigningKey: "some-key",
          secret,
          appBaseUrl: "https://example.com",
          routes: getDefaultRoutes(),
          useMtls: true,
          fetch: globalThis.fetch
        });
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeInstanceOf(MtlsError);
      expect((caught as MtlsError).code).toBe(
        MtlsErrorCode.MTLS_INCOMPATIBLE_CLIENT_AUTH
      );
    });

    it("throws MtlsError with code MTLS_INCOMPATIBLE_CLIENT_AUTH when useDPoP is also set", () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      let caught: unknown;
      try {
        new AuthClient({
          transactionStore,
          sessionStore,
          domain: DOMAIN,
          clientId: CLIENT_ID,
          secret,
          appBaseUrl: "https://example.com",
          routes: getDefaultRoutes(),
          useMtls: true,
          useDPoP: true,
          fetch: globalThis.fetch
        });
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeInstanceOf(MtlsError);
      expect((caught as MtlsError).code).toBe(
        MtlsErrorCode.MTLS_INCOMPATIBLE_CLIENT_AUTH
      );
    });

    it("does not throw when useMtls=true and a custom fetch is provided", async () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      expect(
        () =>
          new AuthClient({
            transactionStore,
            sessionStore,
            domain: DOMAIN,
            clientId: CLIENT_ID,
            // No clientSecret — mTLS doesn't need it
            secret,
            appBaseUrl: "https://example.com",
            routes: getDefaultRoutes(),
            useMtls: true,
            fetch: globalThis.fetch
          })
      ).not.toThrow();
    });

    it("does not throw when useMtls=false (default) even without custom fetch", async () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      expect(
        () =>
          new AuthClient({
            transactionStore,
            sessionStore,
            domain: DOMAIN,
            clientId: CLIENT_ID,
            clientSecret: "some-secret",
            secret,
            appBaseUrl: "https://example.com",
            routes: getDefaultRoutes()
            // useMtls defaults to false, no fetch needed
          })
      ).not.toThrow();
    });
  });

  describe("clientMetadata.use_mtls_endpoint_aliases", () => {
    it("sets use_mtls_endpoint_aliases=true on clientMetadata when useMtls=true", () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: globalThis.fetch
      });

      // Access private field through bracket notation for test verification
      expect(
        (authClient as unknown as { clientMetadata: Record<string, unknown> })
          .clientMetadata.use_mtls_endpoint_aliases
      ).toBe(true);
    });

    it("does NOT set use_mtls_endpoint_aliases when useMtls=false", () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        clientSecret: "some-secret",
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes()
      });

      expect(
        (authClient as unknown as { clientMetadata: Record<string, unknown> })
          .clientMetadata.use_mtls_endpoint_aliases
      ).toBeUndefined();
    });
  });

  describe("refresh token revocation on logout (mTLS)", () => {
    it("calls oauth.revocationRequest with the mTLS alias revocation endpoint", async () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
      });

      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          accessToken: "at_123",
          refreshToken: "rt_mtls_123",
          expiresAt: 9999999999
        },
        internal: {
          sid: "sid_123",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const expiration = Math.floor(Date.now() / 1000 + 3600);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout", "https://example.com"),
        { method: "GET", headers }
      );

      await authClient.handleLogout(request);

      expect(oauth.revocationRequest).toHaveBeenCalledOnce();

      const [asArg, clientArg, , tokenArg] = vi.mocked(oauth.revocationRequest)
        .mock.calls[0];

      // oauth4webapi reads revocation_endpoint from `as` honouring use_mtls_endpoint_aliases
      // on clientMetadata — the alias URL must be present in the metadata passed in
      expect(
        (asArg as oauth.AuthorizationServer).mtls_endpoint_aliases
          ?.revocation_endpoint
      ).toBe(`https://mtls.${DOMAIN}/oauth/revoke`);
      expect((clientArg as oauth.Client).use_mtls_endpoint_aliases).toBe(true);
      expect(tokenArg).toBe("rt_mtls_123");
    });
  });

  describe("discovery guard — mtls_endpoint_aliases missing", () => {
    it("returns MtlsError with MTLS_ENDPOINT_ALIASES_MISSING when discovery has no mtls_endpoint_aliases", async () => {
      setupDiscoveryMocks({ mtls_endpoint_aliases: undefined });

      const { transactionStore, sessionStore } = makeStores(secret);
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
      });

      const request = new NextRequest(
        new URL("/auth/login", "https://example.com"),
        { method: "GET" }
      );

      const response = await authClient.handleLogin(request);
      expect(response.status).toBe(500);
    });

    it("returns MtlsError with MTLS_ENDPOINT_ALIASES_MISSING when mtls_endpoint_aliases has no token_endpoint", async () => {
      setupDiscoveryMocks({
        mtls_endpoint_aliases: {
          revocation_endpoint: `https://mtls.${DOMAIN}/oauth/revoke`
        }
      });

      const { transactionStore, sessionStore } = makeStores(secret);
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
      });

      const request = new NextRequest(
        new URL("/auth/login", "https://example.com"),
        { method: "GET" }
      );

      const response = await authClient.handleLogin(request);
      expect(response.status).toBe(500);
    });
  });

  describe("getClientAuth()", () => {
    it("returns TlsClientAuth() when useMtls=true", async () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes(),
        useMtls: true,
        fetch: globalThis.fetch
      });

      // Access private method through bracket notation
      const clientAuth = await (
        authClient as unknown as {
          getClientAuth(): Promise<oauth.ClientAuth>;
        }
      ).getClientAuth();

      expect(oauth.TlsClientAuth).toHaveBeenCalledOnce();
      expect(clientAuth).toEqual({ type: "tls" });
    });

    it("does NOT call TlsClientAuth() when useMtls=false", async () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        clientSecret: "some-secret",
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes()
      });

      await (
        authClient as unknown as {
          getClientAuth(): Promise<oauth.ClientAuth>;
        }
      ).getClientAuth();

      expect(oauth.TlsClientAuth).not.toHaveBeenCalled();
    });

    it("throws when useMtls=false and no clientSecret or signingKey", async () => {
      const { transactionStore, sessionStore } = makeStores(secret);

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DOMAIN,
        clientId: CLIENT_ID,
        // no clientSecret, no signingKey, no useMtls
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes()
      });

      await expect(
        (
          authClient as unknown as {
            getClientAuth(): Promise<oauth.ClientAuth>;
          }
        ).getClientAuth()
      ).rejects.toThrow(
        "The client secret or client assertion signing key must be provided."
      );
    });
  });
});
