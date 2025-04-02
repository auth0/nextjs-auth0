import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ConfigurationError, ConfigurationErrorCode } from "../errors";
import { Auth0Client } from "./client";

describe("Auth0Client", () => {
  // Store original env vars
  const originalEnv = { ...process.env };

  // Define correct environment variable names
  const ENV_VARS = {
    DOMAIN: "AUTH0_DOMAIN",
    CLIENT_ID: "AUTH0_CLIENT_ID",
    CLIENT_SECRET: "AUTH0_CLIENT_SECRET",
    CLIENT_ASSERTION_SIGNING_KEY: "AUTH0_CLIENT_ASSERTION_SIGNING_KEY",
    APP_BASE_URL: "APP_BASE_URL",
    SECRET: "AUTH0_SECRET",
    SCOPE: "AUTH0_SCOPE"
  };

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
    it("should throw ConfigurationError when all required options are missing", () => {
      expect(() => new Auth0Client()).toThrow(ConfigurationError);

      try {
        new Auth0Client();
      } catch (error) {
        const configError = error as ConfigurationError;
        expect(configError).toBeInstanceOf(ConfigurationError);
        expect(configError.code).toBe(
          ConfigurationErrorCode.MISSING_REQUIRED_OPTIONS
        );
        expect(configError.missingOptions).toContain("domain");
        expect(configError.missingOptions).toContain("clientId");
        expect(configError.missingOptions).toContain("clientAuthentication");
        expect(configError.missingOptions).toContain("appBaseUrl");
        expect(configError.missingOptions).toContain("secret");

        // Check that error message contains correct environment variable names
        expect(configError.message).toContain(ENV_VARS.DOMAIN);
        expect(configError.message).toContain(ENV_VARS.CLIENT_ID);
        expect(configError.message).toContain(ENV_VARS.CLIENT_SECRET);
        expect(configError.message).toContain(
          ENV_VARS.CLIENT_ASSERTION_SIGNING_KEY
        );
        expect(configError.message).toContain(ENV_VARS.APP_BASE_URL);
        expect(configError.message).toContain(ENV_VARS.SECRET);
      }
    });

    it("should throw ConfigurationError when some required options are missing", () => {
      // Provide some but not all required options
      const options = {
        domain: "example.auth0.com",
        clientId: "client_123"
      };

      try {
        new Auth0Client(options);
      } catch (error) {
        const configError = error as ConfigurationError;
        expect(configError).toBeInstanceOf(ConfigurationError);
        expect(configError.code).toBe(
          ConfigurationErrorCode.MISSING_REQUIRED_OPTIONS
        );
        // These should be missing
        expect(configError.missingOptions).toContain("clientAuthentication");
        expect(configError.missingOptions).toContain("appBaseUrl");
        expect(configError.missingOptions).toContain("secret");
        // These should not be in the missing list
        expect(configError.missingOptions).not.toContain("domain");
        expect(configError.missingOptions).not.toContain("clientId");

        // Error message should only contain instructions for missing options
        expect(configError.message).toContain(ENV_VARS.CLIENT_SECRET);
        expect(configError.message).toContain(
          ENV_VARS.CLIENT_ASSERTION_SIGNING_KEY
        );
        expect(configError.message).toContain(ENV_VARS.APP_BASE_URL);
        expect(configError.message).toContain(ENV_VARS.SECRET);
        expect(configError.message).not.toContain(`Set ${ENV_VARS.DOMAIN}`);
        expect(configError.message).not.toContain(`Set ${ENV_VARS.CLIENT_ID}`);
      }
    });

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
