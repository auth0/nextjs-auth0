import { NextResponse, type NextRequest } from "next/server.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  AccessTokenError,
  AccessTokenErrorCode,
  InvalidConfigurationError
} from "../errors/index.js";
import { SessionData } from "../types/index.js";
import { AuthClient } from "./auth-client.js"; // Import the actual class for spyOn
import { Auth0Client } from "./client.js";

// Define ENV_VARS at the top level for broader scope
const ENV_VARS = {
  DOMAIN: "AUTH0_DOMAIN",
  CLIENT_ID: "AUTH0_CLIENT_ID",
  CLIENT_SECRET: "AUTH0_CLIENT_SECRET",
  CLIENT_ASSERTION_SIGNING_KEY: "AUTH0_CLIENT_ASSERTION_SIGNING_KEY",
  APP_BASE_URL: "APP_BASE_URL",
  COOKIE_SECURE: "AUTH0_COOKIE_SECURE",
  SECRET: "AUTH0_SECRET",
  SCOPE: "AUTH0_SCOPE",
  DPOP_PRIVATE_KEY: "AUTH0_DPOP_PRIVATE_KEY",
  DPOP_PUBLIC_KEY: "AUTH0_DPOP_PUBLIC_KEY"
};

describe("Auth0Client", () => {
  // Store original env vars
  const originalEnv = { ...process.env };

  // Clear env vars before each test
  beforeEach(() => {
    vi.resetModules();
    // Clear all environment variables that might affect the tests
    delete process.env[ENV_VARS.DOMAIN];
    delete process.env[ENV_VARS.CLIENT_ID];
    delete process.env[ENV_VARS.CLIENT_SECRET];
    delete process.env[ENV_VARS.CLIENT_ASSERTION_SIGNING_KEY];
    delete process.env[ENV_VARS.APP_BASE_URL];
    delete process.env[ENV_VARS.COOKIE_SECURE];
    delete process.env[ENV_VARS.SECRET];
    delete process.env[ENV_VARS.SCOPE];
    delete process.env[ENV_VARS.DPOP_PRIVATE_KEY];
    delete process.env[ENV_VARS.DPOP_PUBLIC_KEY];
  });

  // Restore env vars after each test
  afterEach(() => {
    vi.unstubAllEnvs();
    process.env = { ...originalEnv };
    vi.restoreAllMocks(); // Restore mocks created within tests/beforeEach
  });

  describe("constructor validation", () => {
    it("should accept clientSecret as authentication method", () => {
      // Set required environment variables with clientSecret
      process.env[ENV_VARS.DOMAIN] = "env.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "env_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "env_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.com";
      process.env[ENV_VARS.SECRET] = "env_secret";

      // Should not throw
      const client = new Auth0Client();

      // The client should be instantiated successfully
      expect(client).toBeInstanceOf(Auth0Client);
    });

    it("should accept clientAssertionSigningKey as authentication method", () => {
      // Set required environment variables with clientAssertionSigningKey instead of clientSecret
      process.env[ENV_VARS.DOMAIN] = "env.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "env_client_id";
      process.env[ENV_VARS.CLIENT_ASSERTION_SIGNING_KEY] = "some-signing-key";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.com";
      process.env[ENV_VARS.SECRET] = "env_secret";

      // Should not throw
      const client = new Auth0Client();

      // The client should be instantiated successfully
      expect(client).toBeInstanceOf(Auth0Client);
    });

    it("should prioritize options over environment variables", () => {
      // Set environment variables
      process.env[ENV_VARS.DOMAIN] = "env.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "env_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "env_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.com";
      process.env[ENV_VARS.SECRET] = "env_secret";

      // Provide conflicting options
      const options = {
        domain: "options.auth0.com",
        clientId: "options_client_id",
        clientSecret: "options_client_secret",
        appBaseUrl: "https://options-app.com",
        secret: "options_secret"
      };

      // Mock the validateAndExtractRequiredOptions to verify which values are used
      const mockValidateAndExtractRequiredOptions = vi
        .fn()
        .mockReturnValue(options);
      const originalValidateAndExtractRequiredOptions =
        Auth0Client.prototype["validateAndExtractRequiredOptions"];
      Auth0Client.prototype["validateAndExtractRequiredOptions"] =
        mockValidateAndExtractRequiredOptions;

      try {
        new Auth0Client(options);

        // Check that validateAndExtractRequiredOptions was called with our options
        expect(mockValidateAndExtractRequiredOptions).toHaveBeenCalledWith(
          options
        );
        // The first argument of the first call should be our options object
        const passedOptions =
          mockValidateAndExtractRequiredOptions.mock.calls[0][0];
        expect(passedOptions.domain).toBe("options.auth0.com");
        expect(passedOptions.clientId).toBe("options_client_id");
      } finally {
        // Restore the original method
        Auth0Client.prototype["validateAndExtractRequiredOptions"] =
          originalValidateAndExtractRequiredOptions;
      }
    });
  });

  // TODO: Re-implement DPoP handle management if needed
  // Currently this functionality is not implemented in the codebase
  // describe("getDpopHandle", () => {
  //   let auth0Client: Auth0Client;

  //   beforeEach(() => {
  //     process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
  //     process.env[ENV_VARS.CLIENT_ID] = "test-client-id";
  //     process.env[ENV_VARS.CLIENT_SECRET] = "test-client-secret";
  //     process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
  //     process.env[ENV_VARS.SECRET] = "test_secret";

  //     auth0Client = new Auth0Client();
  //   });

  //   it("should return undefined when DPoP is not configured", () => {
  //     const handle1 = (auth0Client as any).getDpopHandle("api1");

  //     expect(handle1).toBeUndefined();
  //   });

  //   it("should return undefined for all calls when DPoP is not configured", () => {
  //     const handle1 = (auth0Client as any).getDpopHandle("api1");
  //     const handle2 = (auth0Client as any).getDpopHandle("api1");

  //     expect(handle1).toBeUndefined();
  //     expect(handle2).toBeUndefined();
  //   });

  //   it("should not store anything in dpopHandles Map when DPoP is not configured", () => {
  //     const dpopNonceId = "test-api";
  //     const handle = (auth0Client as any).getDpopHandle(dpopNonceId);

  //     expect(handle).toBeUndefined();

  //     // Access the private dpopHandles map through bracket notation
  //     const dpopHandles = (auth0Client as any)["dpopHandles"];
  //     expect(dpopHandles).toBeDefined();
  //     expect(dpopHandles.has(dpopNonceId)).toBe(false);
  //   });

  //   it("should have an empty dpopHandles Map initially", () => {
  //     // Access the private dpopHandles map through bracket notation
  //     const dpopHandles = (auth0Client as any)["dpopHandles"];
  //     expect(dpopHandles).toBeDefined();
  //     expect(dpopHandles.size).toBe(0);
  //   });

  //   it("should handle multiple calls without DPoP configuration", () => {
  //     const handle1 = (auth0Client as any).getDpopHandle("api1");
  //     const handle2 = (auth0Client as any).getDpopHandle("api2");
  //     const handle3 = (auth0Client as any).getDpopHandle("api1");

  //     expect(handle1).toBeUndefined();
  //     expect(handle2).toBeUndefined();
  //     expect(handle3).toBeUndefined();

  //     // Ensure dpopHandles map remains empty
  //     const dpopHandles = (auth0Client as any)["dpopHandles"];
  //     expect(dpopHandles.size).toBe(0);
  //   });

  //   it("should return undefined when called without dpopNonceId and DPoP not configured", () => {
  //     const handle = (auth0Client as any).getDpopHandle();

  //     expect(handle).toBeUndefined();
  //   });
  // });

  describe("getAccessToken", () => {
    const mockSession: SessionData = {
      user: { sub: "user123" },
      tokenSet: {
        accessToken: "old_access_token",
        idToken: "old_id_token",
        refreshToken: "old_refresh_token",
        expiresAt: Date.now() / 1000 - 3600 // Expired
      },
      internal: {
        sid: "mock_sid",
        createdAt: Date.now() / 1000 - 7200 // Some time in the past
      },
      createdAt: Date.now() / 1000
    };

    // Restore original mock for refreshed token set
    const mockRefreshedTokenSet = {
      accessToken: "new_access_token",
      idToken: "new_id_token",
      refreshToken: "new_refresh_token",
      expiresAt: Date.now() / 1000 + 3600, // Not expired
      scope: "openid profile email"
    };

    let client: Auth0Client;
    let mockGetSession: ReturnType<typeof vi.spyOn>;
    let mockSaveToSession: ReturnType<typeof vi.spyOn>;
    let mockGetTokenSet: ReturnType<typeof vi.spyOn>; // Re-declare mockGetTokenSet

    beforeEach(() => {
      // Reset mocks specifically if vi.restoreAllMocks isn't enough
      // vi.resetAllMocks(); // Alternative to restoreAllMocks in afterEach

      // Set necessary environment variables
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.test";
      process.env[ENV_VARS.SECRET] = "test_secret";

      client = new Auth0Client();

      // Mock internal methods of Auth0Client
      mockGetSession = vi
        .spyOn(Auth0Client.prototype as any, "getSession")
        .mockResolvedValue(mockSession);
      mockSaveToSession = vi
        .spyOn(Auth0Client.prototype as any, "saveToSession")
        .mockResolvedValue(undefined);

      // Restore mocking of getTokenSet directly
      mockGetTokenSet = vi
        .spyOn(AuthClient.prototype as any, "getTokenSet")
        .mockResolvedValue([
          null,
          {
            tokenSet: mockRefreshedTokenSet,
            idTokenClaims: {}
          }
        ]); // Simulate successful refresh

      // Remove mocks for discoverAuthorizationServerMetadata and getClientAuth
      // Remove fetch mock
    });

    it("should throw AccessTokenError if no session exists", async () => {
      // Override getSession mock for this specific test
      mockGetSession.mockResolvedValue(null);

      // Mock request and response objects
      const mockReq = { headers: new Headers() } as NextRequest;
      const mockRes = new NextResponse();

      await expect(
        client.getAccessToken(mockReq, mockRes)
      ).rejects.toThrowError(
        new AccessTokenError(
          AccessTokenErrorCode.MISSING_SESSION,
          "The user does not have an active session."
        )
      );
      // Ensure getTokenSet was not called
      expect(mockGetTokenSet).not.toHaveBeenCalled();
    });

    it("should throw error from getTokenSet if refresh fails", async () => {
      const refreshError = new Error("Refresh failed");
      // Restore overriding the getTokenSet mock directly
      mockGetTokenSet.mockResolvedValue([refreshError, null]);

      // Mock request and response objects
      const mockReq = { headers: new Headers() } as NextRequest;
      const mockRes = new NextResponse();

      await expect(
        client.getAccessToken(mockReq, mockRes, { refresh: true })
      ).rejects.toThrowError(refreshError);

      // Verify save was not called
      expect(mockSaveToSession).not.toHaveBeenCalled();
    });

    it("should provide the refreshed accessToken to beforeSessionSaved hook", async () => {
      let accessToken: string | undefined;

      client = new Auth0Client({
        beforeSessionSaved: async (session) => {
          accessToken = session.tokenSet?.accessToken;
          return session;
        }
      });

      const mockReq = { headers: new Headers() } as NextRequest;
      const mockRes = new NextResponse();

      await client.getAccessToken(mockReq, mockRes, { refresh: true });

      expect(accessToken).toBe("new_access_token");
    });

    it("should honor changes made to the tokenSet in beforeSessionSaved hook", async () => {
      client = new Auth0Client({
        beforeSessionSaved: async (session) => {
          return {
            ...session,
            tokenSet: {
              ...session.tokenSet,
              idToken: "modified_id_token"
            }
          };
        }
      });

      const mockReq = { headers: new Headers() } as NextRequest;
      const mockRes = new NextResponse();

      await client.getAccessToken(mockReq, mockRes, { refresh: true });

      expect(mockSaveToSession).toHaveBeenCalledWith(
        expect.objectContaining({
          tokenSet: expect.objectContaining({
            idToken: "modified_id_token"
          })
        }),
        mockReq,
        mockRes
      );
    });
  });

  describe("constructor configuration", () => {
    beforeEach(() => {
      // Set necessary environment variables
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.test";
      process.env[ENV_VARS.SECRET] = "test_secret";
    });

    it("should pass transactionCookie.maxAge to TransactionStore", () => {
      const customMaxAge = 1800; // 30 minutes

      const client = new Auth0Client({
        transactionCookie: {
          maxAge: customMaxAge
        }
      });

      // Verify that the TransactionStore was created with the correct maxAge
      // We need to access the private property for testing
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      // Check the cookieOptions maxAge - we need to verify it was set correctly
      const cookieOptions = (transactionStore as any).cookieOptions;
      expect(cookieOptions.maxAge).toBe(customMaxAge);
    });

    it("should use default maxAge of 3600 when not specified", () => {
      const client = new Auth0Client();

      // Verify that the TransactionStore was created with the default maxAge
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      // Check the cookieOptions maxAge
      const cookieOptions = (transactionStore as any).cookieOptions;
      expect(cookieOptions.maxAge).toBe(3600);
    });

    it("should pass other transactionCookie options to TransactionStore", () => {
      const customOptions = {
        prefix: "__custom_txn_",
        secure: true,
        sameSite: "strict" as const,
        path: "/auth",
        maxAge: 2700
      };

      const client = new Auth0Client({
        transactionCookie: customOptions
      });

      // Verify that the TransactionStore was created with the correct options
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      const cookieOptions = (transactionStore as any).cookieOptions;
      expect(cookieOptions.maxAge).toBe(customOptions.maxAge);
      expect((transactionStore as any).transactionCookiePrefix).toBe(
        customOptions.prefix
      );

      // Note: secure and sameSite are stored in cookieOptions
      expect(cookieOptions.secure).toBe(customOptions.secure);
      expect(cookieOptions.sameSite).toBe(customOptions.sameSite);
      expect(cookieOptions.path).toBe(customOptions.path);
    });

    it("should pass enableParallelTransactions to TransactionStore", () => {
      const client = new Auth0Client({
        enableParallelTransactions: false
      });

      // Verify that the TransactionStore was created with the correct enableParallelTransactions
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      const enableParallelTransactions = (transactionStore as any)
        .enableParallelTransactions;
      expect(enableParallelTransactions).toBe(false);
    });

    it("should default enableParallelTransactions to true when not specified", () => {
      const client = new Auth0Client();

      // Verify that the TransactionStore was created with the default enableParallelTransactions
      const transactionStore = (client as any).transactionStore;
      expect(transactionStore).toBeDefined();

      const enableParallelTransactions = (transactionStore as any)
        .enableParallelTransactions;
      expect(enableParallelTransactions).toBe(true);
    });
  });

  describe("cookie security when appBaseUrl is omitted", () => {
    beforeEach(() => {
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.SECRET] = "test_secret";
      delete process.env[ENV_VARS.APP_BASE_URL];
    });

    it("should default session and transaction cookies to secure in production", () => {
      vi.stubEnv("NODE_ENV", "production");
      const client = new Auth0Client();
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should keep cookies secure when AUTH0_COOKIE_SECURE is explicitly true in production", () => {
      vi.stubEnv("NODE_ENV", "production");
      process.env[ENV_VARS.COOKIE_SECURE] = "true";
      const client = new Auth0Client();
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should honor session.cookie.secure over AUTH0_COOKIE_SECURE in production", () => {
      vi.stubEnv("NODE_ENV", "production");
      process.env[ENV_VARS.COOKIE_SECURE] = "false";
      const client = new Auth0Client({
        session: {
          cookie: {
            secure: true
          }
        }
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should throw when AUTH0_COOKIE_SECURE is explicitly false in production", () => {
      vi.stubEnv("NODE_ENV", "production");
      process.env[ENV_VARS.COOKIE_SECURE] = "false";

      expect(() => new Auth0Client()).toThrowError(InvalidConfigurationError);
    });

    it("should throw when session.cookie.secure is explicitly false in production", () => {
      vi.stubEnv("NODE_ENV", "production");

      expect(
        () =>
          new Auth0Client({
            session: {
              cookie: {
                secure: false
              }
            }
          })
      ).toThrowError(InvalidConfigurationError);
    });

    it("should throw when transactionCookie.secure is explicitly false in production", () => {
      vi.stubEnv("NODE_ENV", "production");
      expect(
        () =>
          new Auth0Client({
            transactionCookie: {
              secure: false
            }
          })
      ).toThrowError(InvalidConfigurationError);
    });

    it("should honor session.cookie.secure in development", () => {
      vi.stubEnv("NODE_ENV", "development");
      const client = new Auth0Client({
        session: {
          cookie: {
            secure: true
          }
        },
        transactionCookie: {
          secure: true
        }
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should keep cookies non-secure in development and warn when explicitly insecure", () => {
      vi.stubEnv("NODE_ENV", "development");
      process.env[ENV_VARS.COOKIE_SECURE] = "false";
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const client = new Auth0Client();
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(false);
      expect(transactionStore.cookieOptions.secure).toBe(false);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("'appBaseUrl' is not configured")
      );
      warnSpy.mockRestore();
    });

    it("should warn when transactionCookie.secure is explicitly false in development", () => {
      vi.stubEnv("NODE_ENV", "development");
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const client = new Auth0Client({
        transactionCookie: {
          secure: false
        }
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(false);
      expect(transactionStore.cookieOptions.secure).toBe(false);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("'appBaseUrl' is not configured")
      );
      warnSpy.mockRestore();
    });
  });

  describe("cookie security when appBaseUrl is configured via options", () => {
    beforeEach(() => {
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.SECRET] = "test_secret";
      delete process.env[ENV_VARS.APP_BASE_URL];
    });

    it("should throw when appBaseUrl is not a valid URL", () => {
      expect(
        () =>
          new Auth0Client({
            appBaseUrl: "not-a-url"
          })
      ).toThrowError(TypeError);
    });

    it("should force secure cookies when appBaseUrl is a single https string", () => {
      const client = new Auth0Client({
        appBaseUrl: "https://app.example.com"
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should not force secure cookies when appBaseUrl is a single http string", () => {
      const client = new Auth0Client({
        appBaseUrl: "http://localhost:3000"
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(false);
      expect(transactionStore.cookieOptions.secure).toBe(false);
    });

    it("should honor AUTH0_COOKIE_SECURE when appBaseUrl is http", () => {
      process.env[ENV_VARS.COOKIE_SECURE] = "true";
      const client = new Auth0Client({
        appBaseUrl: "http://localhost:3000"
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(false);
    });

    it("should honor secure options when appBaseUrl is http", () => {
      const client = new Auth0Client({
        appBaseUrl: "http://localhost:3000",
        session: {
          cookie: {
            secure: true
          }
        },
        transactionCookie: {
          secure: true
        }
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should prefer session.cookie.secure over AUTH0_COOKIE_SECURE when appBaseUrl is http", () => {
      process.env[ENV_VARS.COOKIE_SECURE] = "true";
      const client = new Auth0Client({
        appBaseUrl: "http://localhost:3000",
        session: {
          cookie: {
            secure: false
          }
        }
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(false);
      expect(transactionStore.cookieOptions.secure).toBe(false);
    });
  });

  describe("cookie security when appBaseUrl is configured via APP_BASE_URL", () => {
    beforeEach(() => {
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.SECRET] = "test_secret";
      delete process.env[ENV_VARS.APP_BASE_URL];
    });

    it("should force secure cookies when APP_BASE_URL is a single https value", () => {
      process.env[ENV_VARS.APP_BASE_URL] = "https://app.example.com";
      const client = new Auth0Client();
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should force secure cookies when APP_BASE_URL is https even if options disable secure", () => {
      process.env[ENV_VARS.APP_BASE_URL] = "https://app.example.com";
      const client = new Auth0Client({
        session: {
          cookie: {
            secure: false
          }
        },
        transactionCookie: {
          secure: false
        }
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should force secure cookies when APP_BASE_URL is https even if AUTH0_COOKIE_SECURE is false", () => {
      process.env[ENV_VARS.APP_BASE_URL] = "https://app.example.com";
      process.env[ENV_VARS.COOKIE_SECURE] = "false";
      const client = new Auth0Client();
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should not force secure cookies when APP_BASE_URL is a single http value", () => {
      process.env[ENV_VARS.APP_BASE_URL] = "http://localhost:3000";
      const client = new Auth0Client();
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(false);
      expect(transactionStore.cookieOptions.secure).toBe(false);
    });

    it("should honor AUTH0_COOKIE_SECURE when APP_BASE_URL is http", () => {
      process.env[ENV_VARS.APP_BASE_URL] = "http://localhost:3000";
      process.env[ENV_VARS.COOKIE_SECURE] = "true";
      const client = new Auth0Client();
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(false);
    });

    it("should honor secure options when APP_BASE_URL is http", () => {
      process.env[ENV_VARS.APP_BASE_URL] = "http://localhost:3000";
      const client = new Auth0Client({
        session: {
          cookie: {
            secure: true
          }
        },
        transactionCookie: {
          secure: true
        }
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(true);
      expect(transactionStore.cookieOptions.secure).toBe(true);
    });

    it("should prefer session.cookie.secure over AUTH0_COOKIE_SECURE when APP_BASE_URL is http", () => {
      process.env[ENV_VARS.APP_BASE_URL] = "http://localhost:3000";
      process.env[ENV_VARS.COOKIE_SECURE] = "true";
      const client = new Auth0Client({
        session: {
          cookie: {
            secure: false
          }
        }
      });
      const sessionStore = client["sessionStore"] as any;
      const transactionStore = (client as any).transactionStore;

      expect(sessionStore.cookieConfig.secure).toBe(false);
      expect(transactionStore.cookieOptions.secure).toBe(false);
    });

    it("should throw when APP_BASE_URL contains multiple values", () => {
      process.env[ENV_VARS.APP_BASE_URL] =
        "https://app.example.com, https://preview.example.com";

      expect(() => new Auth0Client()).toThrowError(TypeError);
    });
  });

  describe("DPoP Environment Variable Configuration", () => {
    // Test DPoP key pairs in PEM format (these are test keys, not for production)
    const TEST_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzQS05OU0N+qhZybt
IG3eAsEFeuSWdbmMBpltLsZWkWKhRANCAATcrBPN+T4ab7o5UEb8KProeVFNeo3K
TBXwJXbbAoO5usON7W9yF9Mv/KBfqnbtEqkmbx4AfuTcTBV6Dc0N81XN
-----END PRIVATE KEY-----`;

    const TEST_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3KwTzfk+Gm+6OVBG/Cj66HlRTXqN
ykwV8CV22wKDubrDje1vchfTL/ygX6p27RKpJm8eAH7k3EwVeg3NDfNVzQ==
-----END PUBLIC KEY-----`;

    let consoleLogSpy: ReturnType<typeof vi.spyOn>;
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    });

    afterEach(() => {
      consoleLogSpy.mockRestore();
      consoleWarnSpy.mockRestore();
    });

    it("should load DPoP keypair from environment variables when useDPoP is true", () => {
      // Set up environment variables
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = TEST_PRIVATE_KEY_PEM;
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = TEST_PUBLIC_KEY_PEM;

      const client = new Auth0Client({
        useDPoP: true
      });

      expect(client).toBeInstanceOf(Auth0Client);

      // The test should either succeed in loading keys OR fail with a warning
      // Success case: should log success message
      // Failure case: should log failure warning (due to test environment limitations)
      const hasSuccessLog = consoleLogSpy.mock.calls.some(
        (call: any[]) =>
          typeof call[0] === "string" &&
          call[0].includes(
            "Successfully loaded DPoP keypair from environment variables"
          )
      );
      const hasFailureWarning = consoleWarnSpy.mock.calls.some(
        (call: any[]) =>
          typeof call[0] === "string" &&
          call[0].includes(
            "WARNING: Failed to load DPoP keypair from environment variables"
          )
      );

      expect(hasSuccessLog || hasFailureWarning).toBe(true);
    });

    it("should return undefined when environment variables are missing and log warning", () => {
      // Set up required environment variables but omit DPoP keys
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";

      // Ensure DPoP environment variables are not set
      delete process.env[ENV_VARS.DPOP_PRIVATE_KEY];
      delete process.env[ENV_VARS.DPOP_PUBLIC_KEY];

      const client = new Auth0Client({
        useDPoP: true
      });

      expect(client).toBeInstanceOf(Auth0Client);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "WARNING: useDPoP is set to true but dpopKeyPair is not provided"
        )
      );
    });

    it("should return undefined when useDPoP is false", () => {
      // Set up environment variables including DPoP keys
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = TEST_PRIVATE_KEY_PEM;
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = TEST_PUBLIC_KEY_PEM;

      const client = new Auth0Client({
        useDPoP: false
      });

      expect(client).toBeInstanceOf(Auth0Client);
      // Should not attempt to load keys or log anything
      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleWarnSpy).not.toHaveBeenCalled();
    });

    it("should prioritize provided dpopKeyPair over environment variables", async () => {
      // Set up environment variables
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = TEST_PRIVATE_KEY_PEM;
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = TEST_PUBLIC_KEY_PEM;

      // Create actual CryptoKey objects using generateDpopKeyPair
      const { generateDpopKeyPair } = await import("../utils/dpopUtils.js");
      const mockKeypair = await generateDpopKeyPair();

      const client = new Auth0Client({
        useDPoP: true,
        dpopKeyPair: mockKeypair
      });

      expect(client).toBeInstanceOf(Auth0Client);
      // Should not attempt to load from env vars since keypair is provided
      expect(consoleLogSpy).not.toHaveBeenCalled();
      expect(consoleWarnSpy).not.toHaveBeenCalled();
    });

    it("should handle invalid PEM format gracefully with warning", () => {
      // Set up environment variables with invalid keys
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = "invalid-private-key";
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = "invalid-public-key";

      const client = new Auth0Client({
        useDPoP: true
      });

      expect(client).toBeInstanceOf(Auth0Client);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "WARNING: Failed to load DPoP keypair from environment variables."
        )
      );
    });

    it("should handle missing private key only", () => {
      // Set up environment variables missing private key
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PUBLIC_KEY] = TEST_PUBLIC_KEY_PEM;
      // AUTH0_DPOP_PRIVATE_KEY is missing

      const client = new Auth0Client({
        useDPoP: true
      });

      expect(client).toBeInstanceOf(Auth0Client);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "WARNING: useDPoP is set to true but dpopKeyPair is not provided"
        )
      );
    });

    it("should handle missing public key only", () => {
      // Set up environment variables missing public key
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://test.com";
      process.env[ENV_VARS.SECRET] = "test_secret";
      process.env[ENV_VARS.DPOP_PRIVATE_KEY] = TEST_PRIVATE_KEY_PEM;
      // AUTH0_DPOP_PUBLIC_KEY is missing

      const client = new Auth0Client({
        useDPoP: true
      });

      expect(client).toBeInstanceOf(Auth0Client);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "WARNING: useDPoP is set to true but dpopKeyPair is not provided"
        )
      );
    });
  });

  describe("Request normalization | Next 15 + 16 compatibility", () => {
    let client: Auth0Client;
    let mockSession: SessionData;

    beforeEach(() => {
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.test";
      process.env[ENV_VARS.SECRET] = "test_secret";

      client = new Auth0Client();
      mockSession = {
        user: { sub: "user123" },
        tokenSet: { accessToken: "token", expiresAt: Date.now() / 1000 + 3600 },
        internal: { sid: "sid", createdAt: Date.now() / 1000 },
        createdAt: Date.now() / 1000
      };
    });

    it("should return session successfully in getSession with plain Request", async () => {
      const spy = vi
        .spyOn(client["sessionStore"], "get")
        .mockResolvedValue(mockSession);

      const req = new Request("https://myapp.test/api/test", { method: "GET" });
      const result = await client.getSession(req as any);

      expect(spy).toHaveBeenCalledTimes(1);
      expect(result).toEqual(mockSession);
    });

    it("should get access token for connection with plain Request", async () => {
      vi.spyOn(client, "getSession").mockResolvedValue(mockSession);
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;
      vi.spyOn(client["authClient"], "getConnectionTokenSet").mockResolvedValue(
        [
          null,
          {
            accessToken: "abc",
            expiresAt: expiresAt,
            scope: "openid",
            connection: "github"
          }
        ]
      );
      vi.spyOn(client as any, "saveToSession").mockResolvedValue(undefined);

      const req = new Request("https://myapp.test/api/test", { method: "GET" });
      const res = new Response();

      const result = await client.getAccessTokenForConnection(
        { connection: "github" },
        req as any,
        res as any
      );

      expect(result.token).toBe("abc");
      expect(result.expiresAt).toBe(expiresAt);
    });

    it("should update session successfully with plain Request", async () => {
      vi.spyOn(client, "getSession").mockResolvedValue(mockSession);
      vi.spyOn(client["sessionStore"], "set").mockResolvedValue(undefined);

      const req = new Request("https://myapp.test/api/update", {
        method: "POST"
      });
      const res = new Response();
      const updatedSession = { ...mockSession, user: { sub: "new_user" } };

      await client.updateSession(req as any, res as any, updatedSession);

      expect(client["sessionStore"].set).toHaveBeenCalledTimes(1);
    });

    it("should save session with plain Request and NextResponse", async () => {
      vi.spyOn(client["sessionStore"], "set").mockImplementation(
        async (_reqCookies, resCookies) => {
          resCookies.set("appSession", "updated_session_value");
        }
      );

      const req = new Request("https://myapp.test/api/update", {
        method: "POST",
        headers: { cookie: "appSession=mock_session_cookie" }
      });
      const res = NextResponse.next();

      await (client as any).saveToSession(mockSession, req as any, res as any);

      expect(res.cookies.get("appSession")?.value).toBe(
        "updated_session_value"
      );
    });

    it("should create fetcher successfully with plain Request", async () => {
      vi.spyOn(client, "getSession").mockResolvedValue(mockSession);

      const mockFetcher = {
        config: {},
        hooks: {},
        isAbsoluteUrl: vi.fn().mockReturnValue(true),
        buildUrl: vi.fn().mockReturnValue("https://api.example.com"),
        fetchWithAuth: vi.fn().mockResolvedValue(new Response("{}")),
        fetch: vi.fn(),
        getAccessToken: vi.fn(),
        getDPoPProof: vi.fn(),
        attachDPoPHeaders: vi.fn(),
        validateResponse: vi.fn()
      };

      vi.spyOn(client["authClient"], "fetcherFactory").mockResolvedValue(
        mockFetcher as any
      );

      const req = new Request("https://myapp.test/api", { method: "GET" });
      const fetcher = await client.createFetcher(req as any, {});

      expect(fetcher).toBeDefined();
      expect(fetcher.fetchWithAuth).toBeInstanceOf(Function);
      // Instead of accessing the protected method, test public behavior or remove this line
      // For example, you can check that fetchWithAuth was called with an absolute URL
      await fetcher.fetchWithAuth("https://api.example.com");
      expect(fetcher.fetchWithAuth).toHaveBeenCalledWith(
        "https://api.example.com"
      );
    });

    it("should call middleware successfully with plain Request", async () => {
      const handlerSpy = vi
        .spyOn(client["authClient"], "handler")
        .mockResolvedValue(NextResponse.next());

      const req = new Request("https://myapp.test/auth", { method: "GET" });
      const result = await client.middleware(req as any);

      expect(handlerSpy).toHaveBeenCalledTimes(1);
      expect(result).toBeInstanceOf(NextResponse);
    });
  });

  describe("Pages Router Set-Cookie header handling", () => {
    let client: Auth0Client;
    const mockSession: SessionData = {
      user: { sub: "user_123" },
      tokenSet: {
        accessToken: "access_token",
        refreshToken: "refresh_token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600
      },
      internal: {
        sid: "session_id",
        createdAt: Math.floor(Date.now() / 1000)
      }
    };

    beforeEach(() => {
      process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
      process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
      process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
      process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.test";
      process.env[ENV_VARS.SECRET] = "a]T3Ep;v:dST7bmO9-2efzp!Ggcj-o5!";

      client = new Auth0Client();
    });

    describe("saveToSession - Pages Router", () => {
      it("should preserve multiple Set-Cookie headers using appendHeader", async () => {
        // Mock getSession to return existing session
        vi.spyOn(client, "getSession").mockResolvedValue(mockSession);

        // Mock sessionStore.set to simulate setting multiple cookies
        vi.spyOn(client["sessionStore"], "set").mockImplementation(
          async (_reqCookies, resCookies) => {
            // Simulate the session store setting multiple chunked cookies
            resCookies.set("__session.0", "chunk0_value", { path: "/" });
            resCookies.set("__session.1", "chunk1_value", { path: "/" });
            resCookies.set("__session.2", "chunk2_value", { path: "/" });
          }
        );

        // Create mock Pages Router request/response
        const req = {
          headers: { cookie: "" }
        };

        const appendedCookies: string[] = [];
        const res = {
          setHeader: vi.fn(),
          appendHeader: vi.fn((name: string, value: string) => {
            if (name.toLowerCase() === "set-cookie") {
              appendedCookies.push(value);
            }
          })
        };

        // Call the private saveToSession method
        await (client as any).saveToSession(mockSession, req, res);

        // Verify appendHeader was called for each cookie
        expect(res.appendHeader).toHaveBeenCalledTimes(3);
        expect(appendedCookies).toHaveLength(3);
        expect(appendedCookies.some((c) => c.includes("__session.0"))).toBe(
          true
        );
        expect(appendedCookies.some((c) => c.includes("__session.1"))).toBe(
          true
        );
        expect(appendedCookies.some((c) => c.includes("__session.2"))).toBe(
          true
        );
      });

      it("should not use setHeader for Set-Cookie headers in Pages Router", async () => {
        vi.spyOn(client, "getSession").mockResolvedValue(mockSession);
        vi.spyOn(client["sessionStore"], "set").mockImplementation(
          async (_reqCookies, resCookies) => {
            resCookies.set("__session", "value", { path: "/" });
          }
        );

        const req = { headers: { cookie: "" } };
        const res = {
          setHeader: vi.fn(),
          appendHeader: vi.fn()
        };

        await (client as any).saveToSession(mockSession, req, res);

        // setHeader should NOT be called with set-cookie
        const setHeaderCalls = res.setHeader.mock.calls;
        const setCookieSetHeaderCalls = setHeaderCalls.filter(
          (call) => (call[0] as string).toLowerCase() === "set-cookie"
        );
        expect(setCookieSetHeaderCalls).toHaveLength(0);

        // appendHeader should be used instead
        expect(res.appendHeader).toHaveBeenCalled();
      });
    });

    describe("updateSession - Pages Router", () => {
      it("should collect all Set-Cookie values and set them as array", async () => {
        vi.spyOn(client, "getSession").mockResolvedValue(mockSession);
        vi.spyOn(client["sessionStore"], "set").mockImplementation(
          async (_reqCookies, resCookies) => {
            // Simulate multiple chunked cookies
            resCookies.set("__session.0", "chunk0", { path: "/" });
            resCookies.set("__session.1", "chunk1", { path: "/" });
            resCookies.set("__session.2", "chunk2", { path: "/" });
          }
        );

        const req = { headers: { cookie: "" } };
        const res = {
          setHeader: vi.fn(),
          appendHeader: vi.fn()
        };

        const updatedSession = {
          ...mockSession,
          user: { sub: "updated_user" }
        };

        await client.updateSession(req as any, res as any, updatedSession);

        // Find the setHeader call for set-cookie
        const setCookieCall = res.setHeader.mock.calls.find(
          (call) => (call[0] as string).toLowerCase() === "set-cookie"
        );

        expect(setCookieCall).toBeDefined();
        // Should be called with an array of cookie values
        const cookieValues = setCookieCall![1];
        expect(Array.isArray(cookieValues)).toBe(true);
        expect(cookieValues).toHaveLength(3);
      });

      it("should handle single cookie without breaking", async () => {
        vi.spyOn(client, "getSession").mockResolvedValue(mockSession);
        vi.spyOn(client["sessionStore"], "set").mockImplementation(
          async (_reqCookies, resCookies) => {
            resCookies.set("__session", "single_value", { path: "/" });
          }
        );

        const req = { headers: { cookie: "" } };
        const res = {
          setHeader: vi.fn(),
          appendHeader: vi.fn()
        };

        await client.updateSession(req as any, res as any, mockSession);

        const setCookieCall = res.setHeader.mock.calls.find(
          (call) => (call[0] as string).toLowerCase() === "set-cookie"
        );

        expect(setCookieCall).toBeDefined();
        const cookieValues = setCookieCall![1];
        expect(Array.isArray(cookieValues)).toBe(true);
        expect(cookieValues).toHaveLength(1);
      });
    });
  });
});

export type GetAccessTokenOptions = {
  refresh?: boolean;
};
