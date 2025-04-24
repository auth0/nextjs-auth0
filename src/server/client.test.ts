import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthClient } from "./auth-client"; // Import the actual class for spyOn
import { Auth0Client } from "./client.js";

// Define ENV_VARS at the top level for broader scope
const ENV_VARS = {
  DOMAIN: "AUTH0_DOMAIN",
  CLIENT_ID: "AUTH0_CLIENT_ID",
  CLIENT_SECRET: "AUTH0_CLIENT_SECRET",
  CLIENT_ASSERTION_SIGNING_KEY: "AUTH0_CLIENT_ASSERTION_SIGNING_KEY",
  APP_BASE_URL: "APP_BASE_URL",
  SECRET: "AUTH0_SECRET",
  SCOPE: "AUTH0_SCOPE"
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
    delete process.env[ENV_VARS.SECRET];
    delete process.env[ENV_VARS.SCOPE];
  });

  // Restore env vars after each test
  afterEach(() => {
    process.env = { ...originalEnv };
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
});

describe("Auth0Client getAccessToken", () => {
  const setupClient = () => {
    // Set required environment variables
    process.env[ENV_VARS.DOMAIN] = "test.auth0.com";
    process.env[ENV_VARS.CLIENT_ID] = "test_client_id";
    process.env[ENV_VARS.CLIENT_SECRET] = "test_client_secret";
    process.env[ENV_VARS.APP_BASE_URL] = "https://myapp.test";
    process.env[ENV_VARS.SECRET] = "test_secret_string_at_least_32_bytes";
    return new Auth0Client();
  };

  beforeEach(() => {
    // Reset mocks before each test
    vi.clearAllMocks();
    // Restore spyOn mocks
    vi.restoreAllMocks();
  });

  it("should call getTokenSet with forceRefresh=true when refresh option is true", async () => {
    const client = setupClient();

    // Define mock session data first
    const mockSession = {
      user: { sub: "user123" },
      tokenSet: {
        accessToken: "initial_at",
        idToken: "initial_idt",
        refreshToken: "initial_rt",
        scope: "openid profile",
        expiresAt: Math.floor(Date.now() / 1000) + 3600 // Not expired
      },
      internal: { sid: "sid123", createdAt: Date.now() / 1000 }
    };
    const refreshedTokenSet = {
      accessToken: "refreshed_at",
      idToken: "refreshed_idt",
      refreshToken: "rotated_rt",
      scope: "openid profile",
      expiresAt: Math.floor(Date.now() / 1000) + 7200
    };

    // Mock getSession directly on the Auth0Client prototype
    vi.spyOn(Auth0Client.prototype, "getSession").mockResolvedValue(
      mockSession
    );

    // Mock getTokenSet directly on the AuthClient prototype
    const getTokenSetSpy = vi
      .spyOn(AuthClient.prototype, "getTokenSet")
      .mockResolvedValue([null, refreshedTokenSet]);

    const result = await client.getAccessToken({ refresh: true });

    // Verify session was checked (by checking our mock of getSession)
    expect(Auth0Client.prototype.getSession).toHaveBeenCalledTimes(1);

    // Verify the spy on getTokenSet was called
    expect(getTokenSetSpy).toHaveBeenCalledTimes(1);
    expect(getTokenSetSpy).toHaveBeenCalledWith(
      mockSession.tokenSet, // The initial token set from session
      true // forceRefresh flag
    );

    // Verify the refreshed token is returned
    expect(result).toEqual({
      token: refreshedTokenSet.accessToken,
      scope: refreshedTokenSet.scope,
      expiresAt: refreshedTokenSet.expiresAt
    });

    // Restore the spy after the test
    getTokenSetSpy.mockRestore();
  });

  // Add other tests for getAccessToken: no session, no refresh token, expired token, etc.
});
