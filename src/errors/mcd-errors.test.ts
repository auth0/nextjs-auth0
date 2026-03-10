/**
 * Tests for MCD-specific error classes
 */

import { describe, expect, it } from "vitest";

import { SdkError } from "../errors/index.js";
import {
  McdBackchannelLogoutError as BackchannelLogoutError,
  DomainResolutionError,
  DomainValidationError,
  McdInvalidConfigurationError as InvalidConfigurationError,
  IssuerValidationError,
  SessionDomainMismatchError
} from "../errors/mcd.js";

describe("MCD Error Classes", () => {
  describe("DomainResolutionError", () => {
    it("should create error with default message", () => {
      const error = new DomainResolutionError();
      expect(error).toBeInstanceOf(SdkError);
      expect(error.message).toBe(
        "Failed to resolve the domain from the request."
      );
      expect(error.name).toBe("DomainResolutionError");
      expect(error.code).toBe("domain_resolution_error");
    });

    it("should create error with custom message", () => {
      const message = "Custom domain resolution message";
      const error = new DomainResolutionError(message);
      expect(error.message).toBe(message);
      expect(error.name).toBe("DomainResolutionError");
      expect(error.code).toBe("domain_resolution_error");
    });

    it("should accept cause error", () => {
      const cause = new Error("Underlying error");
      const error = new DomainResolutionError("Failed to resolve", cause);
      expect(error.cause).toBe(cause);
      expect(error.message).toBe("Failed to resolve");
    });

    it("should have public code property", () => {
      const error = new DomainResolutionError();
      expect(error.code).toBe("domain_resolution_error");
      expect(typeof error.code).toBe("string");
    });
  });

  describe("DomainValidationError", () => {
    it("should create error with default message", () => {
      const error = new DomainValidationError();
      expect(error).toBeInstanceOf(SdkError);
      expect(error.message).toBe("The domain failed validation.");
      expect(error.name).toBe("DomainValidationError");
      expect(error.code).toBe("domain_validation_error");
    });

    it("should create error with custom message", () => {
      const message = "Invalid domain format";
      const error = new DomainValidationError(message);
      expect(error.message).toBe(message);
      expect(error.name).toBe("DomainValidationError");
      expect(error.code).toBe("domain_validation_error");
    });

    it("should extend SdkError", () => {
      const error = new DomainValidationError("test");
      expect(error).toBeInstanceOf(SdkError);
      expect(error).toBeInstanceOf(Error);
    });
  });

  describe("IssuerValidationError", () => {
    it("should create error with expected and actual issuer", () => {
      const expectedIssuer = "https://expected.auth0.com/";
      const actualIssuer = "https://actual.auth0.com/";
      const error = new IssuerValidationError(expectedIssuer, actualIssuer);

      expect(error).toBeInstanceOf(SdkError);
      expect(error.name).toBe("IssuerValidationError");
      expect(error.code).toBe("issuer_validation_error");
      expect(error.expectedIssuer).toBe(expectedIssuer);
      expect(error.actualIssuer).toBe(actualIssuer);
    });

    it("should include issuer mismatch in message", () => {
      const expectedIssuer = "https://expected.auth0.com/";
      const actualIssuer = "https://actual.auth0.com/";
      const error = new IssuerValidationError(expectedIssuer, actualIssuer);

      expect(error.message).toContain("expected");
      expect(error.message).toContain(expectedIssuer);
      expect(error.message).toContain(actualIssuer);
      expect(error.message).toContain("Mismatch");
    });

    it("should expose expectedIssuer publicly", () => {
      const expectedIssuer = "https://expected.auth0.com/";
      const actualIssuer = "https://actual.auth0.com/";
      const error = new IssuerValidationError(expectedIssuer, actualIssuer);

      expect(error.expectedIssuer).toBe(expectedIssuer);
      expect(typeof error.expectedIssuer).toBe("string");
    });

    it("should expose actualIssuer publicly", () => {
      const expectedIssuer = "https://expected.auth0.com/";
      const actualIssuer = "https://actual.auth0.com/";
      const error = new IssuerValidationError(expectedIssuer, actualIssuer);

      expect(error.actualIssuer).toBe(actualIssuer);
      expect(typeof error.actualIssuer).toBe("string");
    });

    it("should handle different issuer formats", () => {
      const expectedIssuer = "https://tenant1.region.auth0.com/";
      const actualIssuer = "https://tenant2.region.auth0.com/";
      const error = new IssuerValidationError(expectedIssuer, actualIssuer);

      expect(error.expectedIssuer).toBe(expectedIssuer);
      expect(error.actualIssuer).toBe(actualIssuer);
    });
  });

  describe("InvalidConfigurationError", () => {
    it("should create error with default message", () => {
      const error = new InvalidConfigurationError();
      expect(error).toBeInstanceOf(SdkError);
      expect(error.message).toContain("MCD configuration");
      expect(error.message.toLowerCase()).toContain("domain string");
      expect(error.message.toLowerCase()).toContain("domainresolver function");
      expect(error.name).toBe("McdInvalidConfigurationError");
      expect(error.code).toBe("invalid_configuration");
    });

    it("should create error with custom message", () => {
      const message = "Missing required configuration";
      const error = new InvalidConfigurationError(message);
      expect(error.message).toBe(message);
      expect(error.name).toBe("McdInvalidConfigurationError");
      expect(error.code).toBe("invalid_configuration");
    });

    it("should be catchable as SdkError", () => {
      const error = new InvalidConfigurationError();
      expect(error).toBeInstanceOf(SdkError);
    });
  });

  describe("SessionDomainMismatchError", () => {
    it("should create error with default message", () => {
      const error = new SessionDomainMismatchError();
      expect(error).toBeInstanceOf(SdkError);
      expect(error.message).toContain("session domain");
      expect(error.message).toContain("request domain");
      expect(error.name).toBe("SessionDomainMismatchError");
      expect(error.code).toBe("session_domain_mismatch");
    });

    it("should create error with custom message", () => {
      const message = "Session from different domain";
      const error = new SessionDomainMismatchError(message);
      expect(error.message).toBe(message);
      expect(error.name).toBe("SessionDomainMismatchError");
      expect(error.code).toBe("session_domain_mismatch");
    });

    it("should be marked as internal but extendable", () => {
      const error = new SessionDomainMismatchError();
      expect(error).toBeInstanceOf(SdkError);
      expect(error.code).toBe("session_domain_mismatch");
    });
  });

  describe("BackchannelLogoutError", () => {
    it("should create error with default message", () => {
      const error = new BackchannelLogoutError();
      expect(error).toBeInstanceOf(SdkError);
      expect(error.message).toContain("backchannel logout");
      expect(error.name).toBe("McdBackchannelLogoutError");
      expect(error.code).toBe("backchannel_logout_error");
    });

    it("should create error with custom message", () => {
      const message = "Logout request validation failed";
      const error = new BackchannelLogoutError(message);
      expect(error.message).toBe(message);
      expect(error.name).toBe("McdBackchannelLogoutError");
      expect(error.code).toBe("backchannel_logout_error");
    });

    it("should extend SdkError", () => {
      const error = new BackchannelLogoutError();
      expect(error).toBeInstanceOf(SdkError);
      expect(error).toBeInstanceOf(Error);
    });
  });

  describe("error inheritance", () => {
    it("DomainResolutionError should extend SdkError", () => {
      const error = new DomainResolutionError();
      expect(error instanceof SdkError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it("DomainValidationError should extend SdkError", () => {
      const error = new DomainValidationError();
      expect(error instanceof SdkError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it("IssuerValidationError should extend SdkError", () => {
      const error = new IssuerValidationError("https://a", "https://b");
      expect(error instanceof SdkError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it("InvalidConfigurationError should extend SdkError", () => {
      const error = new InvalidConfigurationError();
      expect(error instanceof SdkError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it("SessionDomainMismatchError should extend SdkError", () => {
      const error = new SessionDomainMismatchError();
      expect(error instanceof SdkError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it("BackchannelLogoutError should extend SdkError", () => {
      const error = new BackchannelLogoutError();
      expect(error instanceof SdkError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });
  });

  describe("error codes", () => {
    it("should have unique error codes", () => {
      const errors = [
        new DomainResolutionError(),
        new DomainValidationError(),
        new IssuerValidationError("a", "b"),
        new InvalidConfigurationError(),
        new SessionDomainMismatchError(),
        new BackchannelLogoutError()
      ];

      const codes = errors.map((e) => e.code);
      const uniqueCodes = new Set(codes);

      expect(uniqueCodes.size).toBe(codes.length);
    });

    it("should have matching error names and codes pattern", () => {
      const testCases = [
        {
          error: new DomainResolutionError(),
          expectedCode: "domain_resolution_error"
        },
        {
          error: new DomainValidationError(),
          expectedCode: "domain_validation_error"
        },
        {
          error: new IssuerValidationError("a", "b"),
          expectedCode: "issuer_validation_error"
        },
        {
          error: new InvalidConfigurationError(),
          expectedCode: "invalid_configuration"
        },
        {
          error: new SessionDomainMismatchError(),
          expectedCode: "session_domain_mismatch"
        },
        {
          error: new BackchannelLogoutError(),
          expectedCode: "backchannel_logout_error"
        }
      ];

      testCases.forEach(({ error, expectedCode }) => {
        expect(error.code).toBe(expectedCode);
      });
    });
  });

  describe("error messages", () => {
    it("should have descriptive error messages", () => {
      const errors = [
        new DomainResolutionError(),
        new DomainValidationError(),
        new IssuerValidationError(
          "https://expected.auth0.com/",
          "https://actual.auth0.com/"
        ),
        new InvalidConfigurationError(),
        new SessionDomainMismatchError(),
        new BackchannelLogoutError()
      ];

      errors.forEach((error) => {
        expect(error.message).toBeTruthy();
        expect(error.message.length).toBeGreaterThan(0);
        expect(typeof error.message).toBe("string");
      });
    });
  });

  describe("cause handling", () => {
    it("should support cause parameter in DomainResolutionError", () => {
      const underlyingError = new Error("Network timeout");
      const error = new DomainResolutionError(
        "Failed to resolve domain",
        underlyingError
      );

      expect(error.cause).toBe(underlyingError);
      expect(error.cause?.message).toBe("Network timeout");
    });

    it("should handle cause as optional", () => {
      const error = new DomainResolutionError("Failed to resolve");
      expect(error.cause).toBeUndefined();
    });
  });

  describe("POST-IMPL Error Tests", () => {
    it("[POST-IMPL-8] DomainResolutionError with cause parameter", () => {
      const underlying = new Error("Resolver failed");
      const error = new DomainResolutionError(
        "Domain resolution failed",
        underlying
      );
      expect(error.cause).toBe(underlying);
      expect(error.message).toBe("Domain resolution failed");
    });

    it("[POST-IMPL-9] IssuerValidationError constructor signature", () => {
      const expected = "https://auth1.example.com/";
      const actual = "https://auth2.example.com/";
      const error = new IssuerValidationError(expected, actual);
      expect(error.expectedIssuer).toBe(expected);
      expect(error.actualIssuer).toBe(actual);
    });

    it("[POST-IMPL-10] IssuerValidationError message format", () => {
      const expected = "https://auth1.example.com/";
      const actual = "https://auth2.example.com/";
      const error = new IssuerValidationError(expected, actual);
      expect(error.message).toContain("Issuer Mismatch:");
      expect(error.message).toContain(expected);
      expect(error.message).toContain(actual);
    });
  });
});
