/**
 * Public API contract tests.
 *
 * These tests assert that every symbol currently exported from each package
 * entry-point is still present after a migration or refactor.  A failing test
 * means a breaking change was introduced to the public surface — either a name
 * was removed, renamed, or moved to a different entry-point.
 *
 * Adding new exports is always fine and will NOT break these tests.
 * Removing or renaming an existing export WILL break them — intentionally.
 */

import { describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// @auth0/nextjs-auth0/server
// ---------------------------------------------------------------------------
describe("@auth0/nextjs-auth0/server — public exports", () => {
  it("exports Auth0Client", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.Auth0Client).toBe("function");
  });

  it("exports TransactionStore", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.TransactionStore).toBe("function");
  });

  it("exports AbstractSessionStore", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.AbstractSessionStore).toBe("function");
  });

  it("exports filterDefaultIdTokenClaims", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.filterDefaultIdTokenClaims).toBe("function");
  });

  it("exports DEFAULT_ID_TOKEN_CLAIMS", async () => {
    const mod = await import("./server/index.js");
    expect(Array.isArray(mod.DEFAULT_ID_TOKEN_CLAIMS)).toBe(true);
  });

  it("exports generateDpopKeyPair", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.generateDpopKeyPair).toBe("function");
  });

  // MFA error classes
  it("exports MfaRequiredError", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.MfaRequiredError).toBe("function");
  });

  it("exports MfaTokenExpiredError", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.MfaTokenExpiredError).toBe("function");
  });

  it("exports MfaTokenInvalidError", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.MfaTokenInvalidError).toBe("function");
  });

  // WithPageAuthRequired is a TypeScript type; no runtime value to assert here.
  // Verify filterDefaultIdTokenClaims is a function (spot-check that helpers module loaded)
  it("exports filterDefaultIdTokenClaims as a function", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.filterDefaultIdTokenClaims).toBe("function");
  });

  // MCD error classes
  it("exports DomainResolutionError", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.DomainResolutionError).toBe("function");
  });

  it("exports DomainValidationError", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.DomainValidationError).toBe("function");
  });

  it("exports IssuerValidationError", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.IssuerValidationError).toBe("function");
  });

  it("exports SessionDomainMismatchError", async () => {
    const mod = await import("./server/index.js");
    expect(typeof mod.SessionDomainMismatchError).toBe("function");
  });
});

// ---------------------------------------------------------------------------
// @auth0/nextjs-auth0/client
// ---------------------------------------------------------------------------
describe("@auth0/nextjs-auth0/client — public exports", () => {
  it("exports useUser hook", async () => {
    const mod = await import("./client/index.js");
    expect(typeof mod.useUser).toBe("function");
  });

  it("exports getAccessToken", async () => {
    const mod = await import("./client/index.js");
    expect(typeof mod.getAccessToken).toBe("function");
  });

  it("exports withPageAuthRequired", async () => {
    const mod = await import("./client/index.js");
    expect(typeof mod.withPageAuthRequired).toBe("function");
  });

  it("exports Auth0Provider", async () => {
    const mod = await import("./client/index.js");
    expect(typeof mod.Auth0Provider).toBe("function");
  });

  it("exports mfa singleton", async () => {
    const mod = await import("./client/index.js");
    expect(mod.mfa).toBeDefined();
    expect(typeof mod.mfa).toBe("object");
  });

  it("exports passwordless singleton", async () => {
    const mod = await import("./client/index.js");
    expect(mod.passwordless).toBeDefined();
    expect(typeof mod.passwordless).toBe("object");
  });

  it("exports passkey singleton", async () => {
    const mod = await import("./client/index.js");
    expect(mod.passkey).toBeDefined();
    expect(typeof mod.passkey).toBe("object");
  });

  it("exports serializeCredential", async () => {
    const mod = await import("./client/index.js");
    expect(typeof mod.serializeCredential).toBe("function");
  });
});

// ---------------------------------------------------------------------------
// @auth0/nextjs-auth0/errors
// ---------------------------------------------------------------------------
describe("@auth0/nextjs-auth0/errors — public exports", () => {
  it("exports SdkError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.SdkError).toBe("function");
  });

  // OAuth / core errors
  const oauthErrors = [
    "OAuth2Error",
    "DiscoveryError",
    "MissingStateError",
    "InvalidStateError",
    "InvalidConfigurationError",
    "AuthorizationError",
    "AuthorizationCodeGrantRequestError",
    "AuthorizationCodeGrantError",
    "BackchannelLogoutError",
    "BackchannelAuthenticationNotSupportedError",
    "BackchannelAuthenticationError",
    "AccessTokenError",
    "AccessTokenErrorCode",
    "AccessTokenForConnectionError",
    "AccessTokenForConnectionErrorCode",
    "CustomTokenExchangeError",
    "CustomTokenExchangeErrorCode"
  ] as const;

  for (const name of oauthErrors) {
    it(`exports ${name}`, async () => {
      const mod = await import("./errors/index.js");
      expect(mod[name]).toBeDefined();
    });
  }

  // DPoP errors
  it("exports DPoPError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.DPoPError).toBe("function");
  });

  it("exports DPoPErrorCode", async () => {
    const mod = await import("./errors/index.js");
    expect(mod.DPoPErrorCode).toBeDefined();
  });

  // mTLS errors
  it("exports MtlsError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.MtlsError).toBe("function");
  });

  it("exports MtlsErrorCode", async () => {
    const mod = await import("./errors/index.js");
    expect(mod.MtlsErrorCode).toBeDefined();
  });

  // Passwordless DB errors
  it("exports PasswordlessDbChallengeError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.PasswordlessDbChallengeError).toBe("function");
  });

  it("exports PasswordlessDbGetTokenError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.PasswordlessDbGetTokenError).toBe("function");
  });

  // My Account / Connected Accounts errors
  it("exports MyAccountApiError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.MyAccountApiError).toBe("function");
  });

  it("exports ConnectAccountError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.ConnectAccountError).toBe("function");
  });

  it("exports ConnectAccountErrorCodes", async () => {
    const mod = await import("./errors/index.js");
    expect(mod.ConnectAccountErrorCodes).toBeDefined();
  });

  // MFA errors
  const mfaErrors = [
    "MfaGetAuthenticatorsError",
    "MfaChallengeError",
    "MfaVerifyError",
    "MfaEnrollmentError",
    "MfaNoAvailableFactorsError",
    "MfaRequiredError",
    "MfaTokenExpiredError",
    "MfaTokenInvalidError",
    "InvalidRequestError"
  ] as const;

  for (const name of mfaErrors) {
    it(`exports ${name}`, async () => {
      const mod = await import("./errors/index.js");
      expect(typeof mod[name]).toBe("function");
    });
  }

  // Popup errors
  const popupErrors = [
    "PopupBlockedError",
    "PopupCancelledError",
    "PopupTimeoutError",
    "PopupInProgressError",
    "ExecutionContextError"
  ] as const;

  for (const name of popupErrors) {
    it(`exports ${name}`, async () => {
      const mod = await import("./errors/index.js");
      expect(typeof mod[name]).toBe("function");
    });
  }

  // Passwordless errors
  it("exports PasswordlessStartError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.PasswordlessStartError).toBe("function");
  });

  it("exports PasswordlessVerifyError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.PasswordlessVerifyError).toBe("function");
  });

  it("exports PasswordlessDbChallengeError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.PasswordlessDbChallengeError).toBe("function");
  });

  it("exports PasswordlessDbGetTokenError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.PasswordlessDbGetTokenError).toBe("function");
  });

  // MCD errors
  it("exports DomainResolutionError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.DomainResolutionError).toBe("function");
  });

  it("exports DomainValidationError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.DomainValidationError).toBe("function");
  });

  it("exports IssuerValidationError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.IssuerValidationError).toBe("function");
  });

  it("exports SessionDomainMismatchError", async () => {
    const mod = await import("./errors/index.js");
    expect(typeof mod.SessionDomainMismatchError).toBe("function");
  });

  // Passkey errors
  const passkeyErrors = [
    "PasskeyRegisterError",
    "PasskeyChallengeError",
    "PasskeyGetTokenError",
    "PasskeyEnrollmentChallengeError",
    "PasskeyEnrollmentVerifyError"
  ] as const;

  for (const name of passkeyErrors) {
    it(`exports ${name}`, async () => {
      const mod = await import("./errors/index.js");
      expect(typeof mod[name]).toBe("function");
    });
  }
});

// ---------------------------------------------------------------------------
// @auth0/nextjs-auth0/testing
// ---------------------------------------------------------------------------
describe("@auth0/nextjs-auth0/testing — public exports", () => {
  it("exports generateSessionCookie", async () => {
    const mod = await import("./testing/index.js");
    expect(typeof mod.generateSessionCookie).toBe("function");
  });

  it("exports GenerateSessionCookieConfig type (runtime shape present)", async () => {
    // Type-only export — just verify the module loads and the function exists
    const mod = await import("./testing/index.js");
    expect(mod.generateSessionCookie).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Error class shape contracts — verify key instance properties survive migration
// ---------------------------------------------------------------------------
describe("Error class shape contracts", () => {
  it("AccessTokenError has .code property", async () => {
    const { AccessTokenError, AccessTokenErrorCode } =
      await import("./errors/index.js");
    const err = new AccessTokenError(
      AccessTokenErrorCode.MISSING_SESSION,
      "msg"
    );
    expect(err.code).toBe(AccessTokenErrorCode.MISSING_SESSION);
    expect(err.message).toBe("msg");
    expect(err instanceof Error).toBe(true);
  });

  it("AccessTokenErrorCode has MISSING_SESSION and SESSION_EXPIRED", async () => {
    const { AccessTokenErrorCode } = await import("./errors/index.js");
    expect(AccessTokenErrorCode.MISSING_SESSION).toBeDefined();
    expect(AccessTokenErrorCode.SESSION_EXPIRED).toBeDefined();
  });

  it("MfaRequiredError has .mfa_token property and correct name", async () => {
    const { MfaRequiredError } = await import("./errors/index.js");
    const err = new MfaRequiredError(
      "needs mfa",
      "tok123",
      undefined,
      undefined
    );
    expect(err.mfa_token).toBe("tok123");
    expect(err.name).toBe("MfaRequiredError");
  });

  it("ConnectAccountErrorCodes has expected keys", async () => {
    const { ConnectAccountErrorCodes } = await import("./errors/index.js");
    expect(ConnectAccountErrorCodes.FAILED_TO_INITIATE).toBeDefined();
    expect(ConnectAccountErrorCodes.FAILED_TO_COMPLETE).toBeDefined();
  });

  it("DPoPErrorCode has DPOP_JKT_CALCULATION_FAILED", async () => {
    const { DPoPErrorCode } = await import("./errors/index.js");
    expect(DPoPErrorCode.DPOP_JKT_CALCULATION_FAILED).toBeDefined();
  });

  it("PasskeyRegisterError has .error and .error_description", async () => {
    const { PasskeyRegisterError } = await import("./errors/index.js");
    const err = new PasskeyRegisterError(
      "passkeys_not_enabled",
      "desc",
      undefined
    );
    expect(err.error).toBe("passkeys_not_enabled");
    expect(err.error_description).toBe("desc");
  });

  it("PasswordlessStartError has .error and .error_description", async () => {
    const { PasswordlessStartError } = await import("./errors/index.js");
    const err = new PasswordlessStartError(
      "bad_connection",
      "Connection not found.",
      undefined
    );
    expect(err.error).toBe("bad_connection");
    expect(err.error_description).toBe("Connection not found.");
  });

  it("IssuerValidationError carries expected and actual issuer", async () => {
    const { IssuerValidationError } = await import("./errors/index.js");
    const err = new IssuerValidationError(
      "https://expected.auth0.com/",
      "https://actual.auth0.com/"
    );
    expect(err.name).toBe("IssuerValidationError");
    expect(err.message).toContain("expected.auth0.com");
    expect(err.message).toContain("actual.auth0.com");
  });

  it("SessionDomainMismatchError has code = session_domain_mismatch", async () => {
    const { SessionDomainMismatchError } = await import("./errors/index.js");
    const err = new SessionDomainMismatchError("domain mismatch");
    expect(err.code).toBe("session_domain_mismatch");
    expect(err.name).toBe("SessionDomainMismatchError");
  });

  it("MtlsError has .code property and correct name", async () => {
    const { MtlsError, MtlsErrorCode } = await import("./errors/index.js");
    const err = new MtlsError(
      MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
      "needs custom fetch"
    );
    expect(err.code).toBe(MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH);
    expect(err.name).toBe("MtlsError");
    expect(err instanceof Error).toBe(true);
  });

  it("MtlsErrorCode has expected keys", async () => {
    const { MtlsErrorCode } = await import("./errors/index.js");
    expect(MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH).toBeDefined();
    expect(MtlsErrorCode.MTLS_ENDPOINT_ALIASES_MISSING).toBeDefined();
    expect(MtlsErrorCode.MTLS_INCOMPATIBLE_CLIENT_AUTH).toBeDefined();
  });

  it("PasswordlessDbChallengeError has .error and .error_description", async () => {
    const { PasswordlessDbChallengeError } = await import("./errors/index.js");
    const err = new PasswordlessDbChallengeError(
      "invalid_connection",
      "Not a database connection."
    );
    expect(err.error).toBe("invalid_connection");
    expect(err.error_description).toBe("Not a database connection.");
    expect(err.name).toBe("PasswordlessDbChallengeError");
  });

  it("PasswordlessDbGetTokenError has .error and .error_description", async () => {
    const { PasswordlessDbGetTokenError } = await import("./errors/index.js");
    const err = new PasswordlessDbGetTokenError(
      "invalid_otp",
      "The OTP is invalid."
    );
    expect(err.error).toBe("invalid_otp");
    expect(err.error_description).toBe("The OTP is invalid.");
    expect(err.name).toBe("PasswordlessDbGetTokenError");
  });
});
