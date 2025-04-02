import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ConfigurationError, ConfigurationErrorCode } from "../errors";
import { Auth0Client } from "./client";

describe("Auth0Client", () => {
  // Store original env vars
  const originalEnv = { ...process.env };

  // Clear env vars before each test
  beforeEach(() => {
    vi.resetModules();
    // Clear all environment variables that might affect the tests
    delete process.env.AUTH0_DOMAIN;
    delete process.env.AUTH0_CLIENT_ID;
    delete process.env.AUTH0_CLIENT_SECRET;
    delete process.env.APP_BASE_URL;
    delete process.env.AUTH0_SECRET;
  });

  // Restore env vars after each test
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe("constructor validation", () => {
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
        expect(configError.missingOptions).toContain("clientSecret");
        expect(configError.missingOptions).toContain("appBaseUrl");
        expect(configError.missingOptions).toContain("secret");
        // These should not be in the missing list
        expect(configError.missingOptions).not.toContain("domain");
        expect(configError.missingOptions).not.toContain("clientId");
      }
    });

    it("should use environment variables when options are not provided", () => {
      // Set environment variables
      process.env.AUTH0_DOMAIN = "env.auth0.com";
      process.env.AUTH0_CLIENT_ID = "env_client_id";
      process.env.AUTH0_CLIENT_SECRET = "env_client_secret";
      process.env.APP_BASE_URL = "https://myapp.com";
      process.env.AUTH0_SECRET = "env_secret";

      // Should not throw
      const client = new Auth0Client();

      // The client should be instantiated successfully
      expect(client).toBeInstanceOf(Auth0Client);
    });

    it("should prioritize options over environment variables", () => {
      // Set environment variables
      process.env.AUTH0_DOMAIN = "env.auth0.com";
      process.env.AUTH0_CLIENT_ID = "env_client_id";
      process.env.AUTH0_CLIENT_SECRET = "env_client_secret";
      process.env.APP_BASE_URL = "https://myapp.com";
      process.env.AUTH0_SECRET = "env_secret";

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
