import * as oauth from "oauth4webapi";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { MtlsError, MtlsErrorCode } from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

vi.mock("oauth4webapi", async () => {
  const actual = await vi.importActual<typeof oauth>("oauth4webapi");
  return {
    ...actual,
    TlsClientAuth: vi.fn(() => ({ type: "tls" })),
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
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
    jwks_uri: `https://${DOMAIN}/.well-known/jwks.json`,
    mtls_endpoint_aliases: {
      token_endpoint: `https://mtls.${DOMAIN}/oauth/token`
    },
    ...overrides
  } as any);
}

describe("mTLS AuthClient", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
    vi.mocked(oauth.TlsClientAuth).mockClear();
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
            clientSecret: "some-secret",
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
          clientSecret: "some-secret",
          secret,
          appBaseUrl: "https://example.com",
          routes: getDefaultRoutes(),
          useMtls: true
        });
      } catch (e) {
        caught = e;
      }

      expect(caught).toBeInstanceOf(MtlsError);
      expect((caught as MtlsError).code).toBe(
        MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH
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
