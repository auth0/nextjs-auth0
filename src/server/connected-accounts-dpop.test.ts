import * as oauth from "oauth4webapi";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { generateDpopKeyPair } from "../utils/dpopUtils.js";
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// Mock oauth4webapi for integration tests
vi.mock("oauth4webapi", async () => {
  const actual = await vi.importActual<typeof oauth>("oauth4webapi");
  return {
    ...actual,
    protectedResourceRequest: vi.fn(),
    isDPoPNonceError: vi.fn(),
    DPoP: vi.fn((client, keyPair) => ({ client, keyPair })), // Simple mock DPoP handle
    generateKeyPair: vi.fn(async () => ({
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey
    })),
    // Mock discovery functions for proper discovery flow
    discoveryRequest: vi.fn(),
    processDiscoveryResponse: vi.fn(),
    customFetch: Symbol("customFetch"),
    allowInsecureRequests: Symbol("allowInsecureRequests")
  };
});

describe("Connected Accounts DPoP Integration Tests", () => {
  let sessionStore: StatelessSessionStore;
  let secret: string;
  let dpopKeyPair: { privateKey: CryptoKey; publicKey: CryptoKey };

  const DEFAULT = {
    domain: "test.auth0.com",
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    appBaseUrl: "https://example.com",
    sub: "user_123",
    accessToken: "at_123",
    connectAccount: {
      authSession: "auth-session-123",
      ticket: "ticket-123",
      connection: "google-oauth2"
    }
  };

  // Mock authorization server
  function getMockAuthorizationServer(
    options: {
      onConnectAccountRequest?: (req: Request) => Promise<void>;
      onCompleteConnectAccountRequest?: (req: Request) => Promise<void>;
    } = {}
  ) {
    const { onConnectAccountRequest, onCompleteConnectAccountRequest } =
      options;

    return async (
      input: RequestInfo | URL,
      init?: RequestInit
    ): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input.toString());

      // Discovery endpoint
      if (url.pathname === "/.well-known/openid_configuration") {
        return Response.json({
          issuer: `https://${DEFAULT.domain}/`,
          authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
          token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
          jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
          end_session_endpoint: `https://${DEFAULT.domain}/v2/logout`
        });
      }

      // Connect Account
      if (url.pathname === "/me/v1/connected-accounts/connect") {
        if (onConnectAccountRequest) {
          await onConnectAccountRequest(new Request(input, init));
        }

        return Response.json(
          {
            connect_uri: `https://${DEFAULT.domain}/connect`,
            auth_session: DEFAULT.connectAccount.authSession,
            connect_params: {
              ticket: DEFAULT.connectAccount.ticket
            },
            expires_in: 300
          },
          { status: 201 }
        );
      }

      // Connect Account complete
      if (url.pathname === "/me/v1/connected-accounts/complete") {
        if (onCompleteConnectAccountRequest) {
          await onCompleteConnectAccountRequest(new Request(input, init));
        }

        return Response.json(
          {
            id: "conn_123",
            connection: DEFAULT.connectAccount.connection,
            access_type: "offline",
            scopes: ["profile", "email"],
            created_at: new Date().toISOString(),
            expires_at: null
          },
          { status: 200 }
        );
      }

      return new Response("Not Found", { status: 404 });
    };
  }

  beforeEach(async () => {
    secret = await generateSecret(32);
    dpopKeyPair = await generateDpopKeyPair();
    sessionStore = new StatelessSessionStore({ secret });

    // Reset mocks
    vi.mocked(oauth.protectedResourceRequest).mockReset();
    vi.mocked(oauth.isDPoPNonceError).mockReset();
    vi.mocked(oauth.DPoP).mockReset();

    // Setup discovery mocks
    vi.mocked(oauth.discoveryRequest).mockResolvedValue(new Response());
    vi.mocked(oauth.processDiscoveryResponse).mockResolvedValue({
      issuer: `https://${DEFAULT.domain}/`,
      authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
      token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
      jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
      end_session_endpoint: `https://${DEFAULT.domain}/v2/logout`
    } as any);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("createConnectAccountTicket authentication", () => {
    it("should use DPoP authentication when DPoP is enabled", async () => {
      // Setup successful DPoP response
      const mockResponse = new Response(
        JSON.stringify({
          connect_uri: `https://${DEFAULT.domain}/connect`,
          auth_session: DEFAULT.connectAccount.authSession,
          connect_params: { ticket: DEFAULT.connectAccount.ticket },
          expires_in: 300
        }),
        { status: 201 }
      );
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValue(mockResponse);
      vi.mocked(oauth.DPoP).mockReturnValue({
        client: {},
        keyPair: {}
      } as any);

      // Create auth client with DPoP enabled
      const authClientWithDPoP = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        dpopKeyPair,
        useDPoP: true,
        fetch: getMockAuthorizationServer({})
      });

      // Call the private method via reflection
      const createConnectAccountTicket = (
        authClientWithDPoP as any
      ).createConnectAccountTicket.bind(authClientWithDPoP);

      const connectAccountRequest = {
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          expiresAt: null,
          scope: 'scope',
          token_type: 'DPoP'
        },
        connection: DEFAULT.connectAccount.connection,
        redirectUri: `${DEFAULT.appBaseUrl}/auth/callback`,
        state: "test-state",
        codeChallenge: "test-challenge",
        codeChallengeMethod: "S256" as const,
        authorizationParams: {}
      };

      const [error, result] = await createConnectAccountTicket(
        connectAccountRequest
      );

      // Verify DPoP was used
      expect(error).toBeNull();
      expect(result).toBeDefined();
      expect(oauth.protectedResourceRequest).toHaveBeenCalledWith(
        DEFAULT.accessToken,
        "POST",
        expect.any(URL),
        expect.any(Headers),
        expect.any(ReadableStream),
        expect.objectContaining({
          DPoP: { client: {}, keyPair: {} }
        })
      );
      expect(oauth.DPoP).toHaveBeenCalledWith(
        expect.anything(), // clientMetadata
        dpopKeyPair
      );
    });

    it("should use Bearer token authentication when DPoP is disabled", async () => {
      // Setup successful response for protectedResourceRequest
      const mockResponse = new Response(
        JSON.stringify({
          connect_uri: `https://${DEFAULT.domain}/connect`,
          auth_session: DEFAULT.connectAccount.authSession,
          connect_params: { ticket: DEFAULT.connectAccount.ticket },
          expires_in: 300
        }),
        { status: 201 }
      );
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValue(mockResponse);

      // Create auth client without DPoP
      const authClientNoDPoP = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        // No DPoP configuration
        fetch: getMockAuthorizationServer({})
      });

      const createConnectAccountTicket = (
        authClientNoDPoP as any
      ).createConnectAccountTicket.bind(authClientNoDPoP);

      const connectAccountRequest = {
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          expiresAt: null,
          scope: 'scope',
          token_type: 'Bearer'
        },
        connection: DEFAULT.connectAccount.connection,
        redirectUri: `${DEFAULT.appBaseUrl}/auth/callback`,
        state: "test-state",
        codeChallenge: "test-challenge",
        codeChallengeMethod: "S256" as const,
        authorizationParams: {}
      };

      const [error, result] = await createConnectAccountTicket(
        connectAccountRequest
      );

      // Verify request succeeded
      expect(error).toBeNull();
      expect(result).toBeDefined();

      // Verify protectedResourceRequest was used (it handles Bearer tokens when DPoP is disabled)
      expect(oauth.protectedResourceRequest).toHaveBeenCalledWith(
        DEFAULT.accessToken,
        "POST",
        expect.any(URL),
        expect.any(Headers),
        expect.any(ReadableStream),
        expect.objectContaining({
          // Should NOT contain DPoP handle when DPoP is disabled
        })
      );

      // Verify the options passed to protectedResourceRequest don't include DPoP
      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      const options = callArgs[5];
      expect(options.DPoP).toBeUndefined();
    });
  });

  describe("completeConnectAccount authentication", () => {
    it("should use DPoP authentication when DPoP is enabled", async () => {
      // Setup successful DPoP response
      const mockResponse = new Response(
        JSON.stringify({
          id: "conn_123",
          connection: DEFAULT.connectAccount.connection,
          access_type: "offline",
          scopes: ["profile", "email"],
          created_at: new Date().toISOString(),
          expires_at: null
        }),
        { status: 200 }
      );
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValue(mockResponse);
      vi.mocked(oauth.DPoP).mockReturnValue({
        client: {},
        keyPair: {}
      } as any);

      // Create auth client with DPoP enabled
      const authClientWithDPoP = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        dpopKeyPair,
        useDPoP: true,
        fetch: getMockAuthorizationServer({})
      });

      // Call the private method via reflection
      const completeConnectAccount = (
        authClientWithDPoP as any
      ).completeConnectAccount.bind(authClientWithDPoP);

      const completeRequest = {
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          expiresAt: null,
          scope: 'scope',
          token_type: 'DPoP'
        },
        authSession: DEFAULT.connectAccount.authSession,
        connectCode: "connect-code-123",
        redirectUri: `${DEFAULT.appBaseUrl}/auth/callback`,
        codeVerifier: "code-verifier"
      };

      const [error, result] = await completeConnectAccount(completeRequest);

      // Verify DPoP was used
      expect(error).toBeNull();
      expect(result).toBeDefined();
      expect(oauth.protectedResourceRequest).toHaveBeenCalledWith(
        DEFAULT.accessToken,
        "POST",
        expect.any(URL),
        expect.any(Headers),
        expect.any(ReadableStream),
        expect.objectContaining({
          DPoP: { client: {}, keyPair: {} }
        })
      );
      expect(oauth.DPoP).toHaveBeenCalledWith(
        expect.anything(), // clientMetadata
        dpopKeyPair
      );
    });

    it("should use Bearer token authentication when DPoP is disabled", async () => {
      // Setup successful response for protectedResourceRequest
      const mockResponse = new Response(
        JSON.stringify({
          id: "conn_123",
          connection: DEFAULT.connectAccount.connection,
          access_type: "offline",
          scopes: ["profile", "email"],
          created_at: new Date().toISOString(),
          expires_at: null
        }),
        { status: 200 }
      );
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValue(mockResponse);

      // Create auth client without DPoP
      const authClientNoDPoP = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        // No DPoP configuration
        fetch: getMockAuthorizationServer({})
      });

      const completeConnectAccount = (
        authClientNoDPoP as any
      ).completeConnectAccount.bind(authClientNoDPoP);

      const completeRequest = {
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          expiresAt: null,
          scope: 'scope',
          token_type: 'Bearer'
        },
        authSession: DEFAULT.connectAccount.authSession,
        connectCode: "connect-code-123",
        redirectUri: `${DEFAULT.appBaseUrl}/auth/callback`,
        codeVerifier: "code-verifier"
      };

      const [error, result] = await completeConnectAccount(completeRequest);

      // Verify request succeeded
      expect(error).toBeNull();
      expect(result).toBeDefined();

      // Verify protectedResourceRequest was used (it handles Bearer tokens when DPoP is disabled)
      expect(oauth.protectedResourceRequest).toHaveBeenCalledWith(
        DEFAULT.accessToken,
        "POST",
        expect.any(URL),
        expect.any(Headers),
        expect.any(ReadableStream),
        expect.objectContaining({
          // Should NOT contain DPoP handle when DPoP is disabled
        })
      );

      // Verify the options passed to protectedResourceRequest don't include DPoP
      const callArgs = (oauth.protectedResourceRequest as any).mock.calls[0];
      const options = callArgs[5];
      expect(options.DPoP).toBeUndefined();
    });
  });

  describe("DPoP misconfigured behavior", () => {
    it("should throw an error when DPoP is enabled but dpopKeyPair is missing", async () => {
      // Setup successful response for protectedResourceRequest
      const mockResponse = new Response(
        JSON.stringify({
          connect_uri: `https://${DEFAULT.domain}/connect`,
          auth_session: DEFAULT.connectAccount.authSession,
          connect_params: { ticket: DEFAULT.connectAccount.ticket },
          expires_in: 300
        }),
        { status: 201 }
      );
      vi.mocked(oauth.protectedResourceRequest).mockResolvedValue(mockResponse);

      // Create auth client with DPoP enabled but no key pair
      const authClientDPoPNoKeys = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        useDPoP: true,
        // dpopKeyPair intentionally omitted
        fetch: getMockAuthorizationServer({})
      });

      const createConnectAccountTicket = (
        authClientDPoPNoKeys as any
      ).createConnectAccountTicket.bind(authClientDPoPNoKeys);

      const connectAccountRequest = {
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          expiresAt: null,
          scope: 'scope',
          token_type: 'Bearer'
        },
        connection: DEFAULT.connectAccount.connection,
        redirectUri: `${DEFAULT.appBaseUrl}/auth/callback`,
        state: "test-state",
        codeChallenge: "test-challenge",
        codeChallengeMethod: "S256" as const,
        authorizationParams: {}
      };

      const [error, result] = await createConnectAccountTicket(
        connectAccountRequest
      );

      // Verify it fell back to Bearer tokens
      expect(error).not.toBeNull();
      expect(result).toBeNull();

      expect(error.message).toBe("DPoP is enabled but no keypair is configured.");
    });
  });
});
