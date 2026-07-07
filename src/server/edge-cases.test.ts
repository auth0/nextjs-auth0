/**
 * Edge case tests — logic paths that have unusual or boundary conditions:
 *
 * Covered here:
 * 1. handlePasswordlessStart  — unexpected_error/SdkError/bare error fallbacks
 * 2. handlePasswordlessVerify — unexpected_error/discovery_error/SdkError/bare fallbacks
 * 3. handlePasswordlessDbOtpChallenge — unexpected_error/SdkError/bare fallbacks
 * 4. handlePasswordlessDbGetToken — unexpected_error/SdkError/bare fallbacks
 * 5. handleVerify (mfaVerify route) — no-session + id_token path; missing_session throw
 * 6. mfa-transform-utils — transformVerifyBodyToOptions missing credential; buildVerifyParams no credential; getVerifyGrantType no credential
 * 7. mfa-utils handleMfaError — non-SdkError wrap path
 * 8. passkeyGetToken — JWT claim mismatch (invalid_issuer / invalid_audience)
 * 9. getTokenSet — mfa_required without mfa_token (re-auth needed)
 * 10. token-set-helpers — normalizeExpiresAt empty-string and NaN paths
 * 11. normalize-session — legacy stateless and stateful session normalization
 * 12. discovery-cache — JWKS LRU eviction
 * 13. DPoP JKT calculation failure
 */

import { NextRequest, NextResponse } from "next/server.js";
import * as jose from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DPoPErrorCode,
  InvalidConfigurationError,
  MfaVerifyError,
  PasswordlessDbChallengeError,
  PasswordlessDbGetTokenError,
  PasswordlessStartError,
  PasswordlessVerifyError
} from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import {
  buildVerifyParams,
  getVerifyGrantType,
  transformVerifyBodyToOptions
} from "../utils/mfa-transform-utils.js";
import { encryptMfaToken, handleMfaError } from "../utils/mfa-utils.js";
import { normalizeExpiresAt } from "../utils/token-set-helpers.js";
import { AuthClient } from "./auth-client.js";
import { DiscoveryCache } from "./discovery-cache.js";
import {
  normalizeStatefulSession,
  normalizeStatelessSession
} from "./session/normalize-session.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

const DOMAIN = "guabu.us.auth0.com";
const CLIENT_ID = "client_123";
const CLIENT_SECRET = "client-secret";
const APP_BASE_URL = "https://example.com";

const _authorizationServerMetadata = {
  issuer: `https://${DOMAIN}/`,
  authorization_endpoint: `https://${DOMAIN}/authorize`,
  token_endpoint: `https://${DOMAIN}/oauth/token`,
  userinfo_endpoint: `https://${DOMAIN}/userinfo`,
  mfa_challenge_endpoint: `https://${DOMAIN}/mfa/challenge`,
  jwks_uri: `https://${DOMAIN}/.well-known/jwks.json`,
  registration_endpoint: `https://${DOMAIN}/oidc/register`,
  revocation_endpoint: `https://${DOMAIN}/oauth/revoke`,
  scopes_supported: ["openid", "profile", "offline_access", "email"],
  response_types_supported: ["code"],
  code_challenge_methods_supported: ["S256"],
  response_modes_supported: ["query", "fragment", "form_post"],
  subject_types_supported: ["public"],
  token_endpoint_auth_methods_supported: [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt"
  ],
  claims_supported: ["aud", "auth_time", "exp", "iat", "iss", "sub"],
  request_uri_parameter_supported: false,
  request_parameter_supported: false,
  id_token_signing_alg_values_supported: ["RS256"],
  token_endpoint_auth_signing_alg_values_supported: ["RS256"],
  backchannel_logout_supported: true,
  backchannel_logout_session_supported: true,
  end_session_endpoint: `https://${DOMAIN}/oidc/logout`,
  pushed_authorization_request_endpoint: `https://${DOMAIN}/oauth/par`,
  backchannel_authentication_endpoint: `https://${DOMAIN}/bc-authorize`,
  backchannel_token_delivery_modes_supported: ["poll"]
};

function makeMinimalFetch(
  overrides?: (url: URL, init?: RequestInit) => Response | null
) {
  const keyPairPromise = jose.generateKeyPair("RS256");
  return vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url =
        input instanceof Request
          ? new URL(input.url)
          : new URL(input as string);
      if (overrides) {
        const r = overrides(url, init);
        if (r !== null) return r;
      }
      if (url.pathname === "/.well-known/openid-configuration") {
        return Response.json(_authorizationServerMetadata);
      }
      if (url.pathname === "/.well-known/jwks.json") {
        const kp = await keyPairPromise;
        const pub = await jose.exportJWK(kp.publicKey);
        return Response.json({ keys: [pub] });
      }
      return new Response(null, { status: 404 });
    }
  );
}

async function makeAuthClient(
  secret: string,
  fetchMock: ReturnType<typeof vi.fn>,
  extra: Record<string, unknown> = {}
) {
  const transactionStore = new TransactionStore({ secret });
  const sessionStore = new StatelessSessionStore({ secret });
  return new AuthClient({
    transactionStore,
    sessionStore,
    domain: DOMAIN,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    secret,
    appBaseUrl: APP_BASE_URL,
    routes: getDefaultRoutes(),
    fetch: fetchMock,
    ...extra
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// 1. handlePasswordlessStart — error fallbacks
// ---------------------------------------------------------------------------

describe("handlePasswordlessStart — error fallbacks", () => {
  it("returns 500 with server_error when PasswordlessStartError.error === unexpected_error", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessStart").mockRejectedValue(
      new PasswordlessStartError("unexpected_error", "Internal failure")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/start", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "email",
          email: "u@example.com",
          send: "code"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessStart(req);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
  });

  it("returns 400 with error JSON when PasswordlessStartError.error is not unexpected_error", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessStart").mockRejectedValue(
      new PasswordlessStartError("bad_connection", "Connection not found.")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/start", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "email",
          email: "u@example.com",
          send: "code"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessStart(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("bad_connection");
  });

  it("returns 400 with SdkError shape when a generic SdkError is thrown", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessStart").mockRejectedValue(
      new InvalidConfigurationError("missing config")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/start", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "sms",
          phoneNumber: "+15550001234"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessStart(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_configuration");
  });

  it("returns 500 with server_error when an unknown non-SDK error is thrown", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessStart").mockRejectedValue(
      new TypeError("unexpected network failure")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/start", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "email",
          email: "u@example.com",
          send: "code"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessStart(req);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
  });
});

// ---------------------------------------------------------------------------
// 2. handlePasswordlessVerify — error fallbacks
// ---------------------------------------------------------------------------

describe("handlePasswordlessVerify — error fallbacks", () => {
  it("returns 500 when PasswordlessVerifyError.error is unexpected_error", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessVerify").mockRejectedValue(
      new PasswordlessVerifyError("unexpected_error", "Server error")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/verify", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "email",
          email: "u@example.com",
          verificationCode: "123456"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessVerify(req);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
  });

  it("returns 500 when PasswordlessVerifyError.error is discovery_error", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessVerify").mockRejectedValue(
      new PasswordlessVerifyError(
        "discovery_error",
        "Could not fetch OIDC config"
      )
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/verify", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "email",
          email: "u@example.com",
          verificationCode: "123456"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessVerify(req);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
  });

  it("returns 403 with error JSON when PasswordlessVerifyError.error is a non-server code", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessVerify").mockRejectedValue(
      new PasswordlessVerifyError(
        "invalid_otp",
        "The OTP is invalid or expired."
      )
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/verify", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "sms",
          phoneNumber: "+15550001234",
          verificationCode: "000000"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessVerify(req);
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("invalid_otp");
  });

  it("returns 400 with SdkError shape when a generic SdkError is thrown", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessVerify").mockRejectedValue(
      new InvalidConfigurationError("missing config")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/verify", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "email",
          email: "u@example.com",
          verificationCode: "123456"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessVerify(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_configuration");
  });

  it("returns 500 with server_error when a non-SDK error is thrown", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessVerify").mockRejectedValue(
      new TypeError("network failure")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/verify", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "email",
          email: "u@example.com",
          verificationCode: "123456"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessVerify(req);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
  });
});

// ---------------------------------------------------------------------------
// 3. handlePasswordlessDbOtpChallenge — error fallbacks
// ---------------------------------------------------------------------------

describe("handlePasswordlessDbOtpChallenge — error fallbacks", () => {
  it("returns 500 when PasswordlessDbChallengeError.error === unexpected_error", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessDbOtpChallenge").mockRejectedValue(
      new PasswordlessDbChallengeError("unexpected_error", "Internal error")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/otp/challenge", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "Username-Password-Authentication",
          email: "u@example.com"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessDbOtpChallenge(req);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
  });

  it("returns 400 when PasswordlessDbChallengeError.error is a non-server code", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessDbOtpChallenge").mockRejectedValue(
      new PasswordlessDbChallengeError("user_not_found", "User not found.")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/otp/challenge", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "Username-Password-Authentication",
          email: "u@example.com"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessDbOtpChallenge(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("user_not_found");
  });

  it("returns 400 with SdkError shape when a generic SdkError is thrown", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessDbOtpChallenge").mockRejectedValue(
      new InvalidConfigurationError("bad config")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/otp/challenge", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "Username-Password-Authentication",
          email: "u@example.com"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessDbOtpChallenge(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_configuration");
  });

  it("returns 500 when a non-SDK error is thrown", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessDbOtpChallenge").mockRejectedValue(
      new TypeError("network error")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/otp/challenge", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({
          connection: "Username-Password-Authentication",
          email: "u@example.com"
        }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessDbOtpChallenge(req);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
  });
});

// ---------------------------------------------------------------------------
// 4. handlePasswordlessDbGetToken — error fallbacks
// ---------------------------------------------------------------------------

describe("handlePasswordlessDbGetToken — error fallbacks", () => {
  it("returns 500 when PasswordlessDbGetTokenError.error === unexpected_error", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessDbGetToken").mockRejectedValue(
      new PasswordlessDbGetTokenError("unexpected_error", "Internal error")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/otp/token", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({ authSession: "sess", otp: "123456" }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessDbGetToken(req);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
  });

  it("returns 400 when PasswordlessDbGetTokenError.error is a non-server code", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessDbGetToken").mockRejectedValue(
      new PasswordlessDbGetTokenError("invalid_otp", "Wrong OTP.")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/otp/token", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({ authSession: "sess", otp: "000000" }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessDbGetToken(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_otp");
  });

  it("returns 400 with SdkError shape when a generic SdkError is thrown", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessDbGetToken").mockRejectedValue(
      new InvalidConfigurationError("bad config")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/otp/token", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({ authSession: "sess", otp: "123456" }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessDbGetToken(req);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_configuration");
  });

  it("returns 500 when a non-SDK error is thrown", async () => {
    const secret = await generateSecret(32);
    const authClient = await makeAuthClient(secret, makeMinimalFetch());

    vi.spyOn(authClient as any, "passwordlessDbGetToken").mockRejectedValue(
      new TypeError("network error")
    );

    const req = new NextRequest(
      new URL("/auth/passwordless/otp/token", APP_BASE_URL),
      {
        method: "POST",
        body: JSON.stringify({ authSession: "sess", otp: "123456" }),
        headers: { "content-type": "application/json" }
      }
    );

    const res = await authClient.handlePasswordlessDbGetToken(req);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
  });
});

// ---------------------------------------------------------------------------
// 5. handleVerify — no-session + id_token path; missing_session throw
// ---------------------------------------------------------------------------

describe("handleVerify — no-session path", () => {
  it("creates a session from mfaVerify result when no session exists and id_token is present", async () => {
    const secret = await generateSecret(32);
    const keyPair = await jose.generateKeyPair("RS256");

    const encryptedToken = await encryptMfaToken(
      "raw-mfa-token",
      "aud",
      "openid profile",
      undefined,
      secret,
      600
    );

    const idToken = await new jose.SignJWT({ sub: "user_123" })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(`https://${DOMAIN}/`)
      .setAudience(CLIENT_ID)
      .setExpirationTime("2h")
      .setIssuedAt()
      .sign(keyPair.privateKey);

    const fetchMock = vi.fn(
      async (
        input: RequestInfo | URL,
        _init?: RequestInit
      ): Promise<Response> => {
        const url =
          input instanceof Request
            ? new URL(input.url)
            : new URL(input as string);
        if (url.pathname === "/.well-known/openid-configuration") {
          return Response.json(_authorizationServerMetadata);
        }
        if (url.pathname === "/.well-known/jwks.json") {
          return Response.json({
            keys: [await jose.exportJWK(keyPair.publicKey)]
          });
        }
        if (url.pathname === "/oauth/token") {
          return Response.json({
            access_token: "at_from_mfa",
            id_token: idToken,
            token_type: "Bearer",
            expires_in: 86400,
            scope: "openid profile"
          });
        }
        return new Response(null, { status: 404 });
      }
    );

    const authClient = await makeAuthClient(secret, fetchMock);

    const req = new NextRequest(new URL("/auth/mfa/verify", APP_BASE_URL), {
      method: "POST",
      body: JSON.stringify({ otp: "123456" }),
      headers: {
        "content-type": "application/json",
        Authorization: `Bearer ${encryptedToken}`
      }
    });

    const res = await authClient.handleVerify(req);
    // Should succeed — no existing session, but id_token present → session created
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });

  it("returns missing_session error when mfaVerify succeeds but no id_token and no session", async () => {
    const secret = await generateSecret(32);

    const encryptedToken = await encryptMfaToken(
      "raw-mfa-token",
      "aud",
      "openid profile",
      undefined,
      secret,
      600
    );

    const fetchMock = makeMinimalFetch((url) => {
      if (url.pathname === "/oauth/token") {
        // Return tokens without id_token, no session exists
        return Response.json({
          access_token: "at_only",
          token_type: "Bearer",
          expires_in: 86400,
          scope: "openid profile"
        });
      }
      return null;
    });

    const authClient = await makeAuthClient(secret, fetchMock);

    const req = new NextRequest(new URL("/auth/mfa/verify", APP_BASE_URL), {
      method: "POST",
      body: JSON.stringify({ otp: "123456" }),
      headers: {
        "content-type": "application/json",
        Authorization: `Bearer ${encryptedToken}`
      }
    });

    const res = await authClient.handleVerify(req);
    // handleMfaError wraps MfaVerifyError(missing_session) into response
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("missing_session");
  });
});

// ---------------------------------------------------------------------------
// 6. mfa-transform-utils — error throw paths
// ---------------------------------------------------------------------------

describe("transformVerifyBodyToOptions — missing credential throws", () => {
  it("throws InvalidRequestError when no valid credential field is present", () => {
    expect(() => transformVerifyBodyToOptions({})).toThrow(
      "Missing verification credential"
    );
    expect(() =>
      transformVerifyBodyToOptions({ some_other_field: "value" })
    ).toThrow();
    expect(() =>
      transformVerifyBodyToOptions({ oob_code: "code_only" })
    ).toThrow();
  });
});

describe("buildVerifyParams — no credential throws", () => {
  it("throws MfaVerifyError when options have no credential fields", () => {
    // Options with mfaToken only — no otp/oobCode/recoveryCode
    const options = { mfaToken: "tok" } as any;
    expect(() => buildVerifyParams(options, "raw-token")).toThrow(
      MfaVerifyError
    );
    expect(() => buildVerifyParams(options, "raw-token")).toThrow(
      "At least one verification credential"
    );
  });
});

describe("getVerifyGrantType — no credential throws", () => {
  it("throws MfaVerifyError when params have no credential key", () => {
    const params = new URLSearchParams();
    params.set("mfa_token", "tok");
    // No otp, oob_code, or recovery_code
    expect(() => getVerifyGrantType(params)).toThrow(MfaVerifyError);
    expect(() => getVerifyGrantType(params)).toThrow(
      "No verification credential"
    );
  });
});

// ---------------------------------------------------------------------------
// 7. mfa-utils handleMfaError — non-SdkError wrap path
// ---------------------------------------------------------------------------

describe("handleMfaError — non-SdkError wrapping", () => {
  it("wraps a plain Error in OAuth2Error with server_error code", () => {
    const plainError = new Error("something exploded");
    const res = handleMfaError(plainError);
    expect(res).toBeInstanceOf(NextResponse);
    expect(res.status).toBe(500);
  });

  it("wraps a non-Error (string) in OAuth2Error with generic message", () => {
    const res = handleMfaError("raw string thrown");
    expect(res).toBeInstanceOf(NextResponse);
    expect(res.status).toBe(500);
  });

  it("passes SdkError through without wrapping", () => {
    const sdkErr = new MfaVerifyError("invalid_otp", "Invalid OTP");
    const res = handleMfaError(sdkErr);
    expect(res).toBeInstanceOf(NextResponse);
    // MfaVerifyError → 400
    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// 8. passkeyGetToken — JWT claim mismatch (invalid_issuer / invalid_audience)
// ---------------------------------------------------------------------------

describe("passkeyGetToken — JWT claim mismatch errors", () => {
  it("throws PasskeyGetTokenError with invalid_issuer when token has wrong issuer", async () => {
    const secret = await generateSecret(32);
    const keyPair = await jose.generateKeyPair("RS256");

    const badIssuerJwt = await new jose.SignJWT({ sub: "user_123" })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer("https://WRONG-ISSUER.auth0.com/")
      .setAudience(CLIENT_ID)
      .setExpirationTime("2h")
      .setIssuedAt()
      .sign(keyPair.privateKey);

    const fetchMock = vi.fn(
      async (
        input: RequestInfo | URL,
        _init?: RequestInit
      ): Promise<Response> => {
        const url =
          input instanceof Request
            ? new URL(input.url)
            : new URL(input as string);
        if (url.pathname === "/.well-known/openid-configuration")
          return Response.json(_authorizationServerMetadata);
        if (url.pathname === "/.well-known/jwks.json") {
          return Response.json({
            keys: [await jose.exportJWK(keyPair.publicKey)]
          });
        }
        if (url.pathname === "/oauth/token") {
          return Response.json({
            access_token: "at",
            id_token: badIssuerJwt,
            token_type: "Bearer",
            expires_in: 86400
          });
        }
        return new Response(null, { status: 404 });
      }
    );

    const authClient = await makeAuthClient(secret, fetchMock);

    await expect(
      (authClient as any).passkeyGetToken({
        authSession: "session",
        authResponse: { id: "cred-id", type: "public-key" }
      })
    ).rejects.toMatchObject({
      name: "PasskeyGetTokenError",
      error: "invalid_issuer"
    });
  });

  it("throws PasskeyGetTokenError with invalid_audience when token has wrong audience", async () => {
    const secret = await generateSecret(32);
    const keyPair = await jose.generateKeyPair("RS256");

    const badAudJwt = await new jose.SignJWT({ sub: "user_123" })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(`https://${DOMAIN}/`)
      .setAudience("WRONG-AUDIENCE")
      .setExpirationTime("2h")
      .setIssuedAt()
      .sign(keyPair.privateKey);

    const fetchMock = vi.fn(
      async (
        input: RequestInfo | URL,
        _init?: RequestInit
      ): Promise<Response> => {
        const url =
          input instanceof Request
            ? new URL(input.url)
            : new URL(input as string);
        if (url.pathname === "/.well-known/openid-configuration")
          return Response.json(_authorizationServerMetadata);
        if (url.pathname === "/.well-known/jwks.json") {
          return Response.json({
            keys: [await jose.exportJWK(keyPair.publicKey)]
          });
        }
        if (url.pathname === "/oauth/token") {
          return Response.json({
            access_token: "at",
            id_token: badAudJwt,
            token_type: "Bearer",
            expires_in: 86400
          });
        }
        return new Response(null, { status: 404 });
      }
    );

    const authClient = await makeAuthClient(secret, fetchMock);

    await expect(
      (authClient as any).passkeyGetToken({
        authSession: "session",
        authResponse: { id: "cred-id", type: "public-key" }
      })
    ).rejects.toMatchObject({
      name: "PasskeyGetTokenError",
      error: "invalid_audience"
    });
  });
});

// ---------------------------------------------------------------------------
// 9. getTokenSet — mfa_required without mfa_token (re-auth needed path)
// ---------------------------------------------------------------------------

describe("getTokenSet — mfa_required without mfa_token", () => {
  it("returns MfaRequiredError with empty mfa_token when token endpoint returns mfa_required without mfa_token", async () => {
    const secret = await generateSecret(32);

    const fetchMock = makeMinimalFetch((url) => {
      if (url.pathname === "/oauth/token") {
        return Response.json(
          {
            error: "mfa_required",
            error_description: "MFA required"
            // No mfa_token field
          },
          { status: 400 }
        );
      }
      return null;
    });

    const authClient = await makeAuthClient(secret, fetchMock);

    const session = {
      user: { sub: "user_123" },
      tokenSet: {
        accessToken: "expired-at",
        refreshToken: "rt_123",
        expiresAt: Math.floor(Date.now() / 1000) - 3600
      },
      internal: { sid: "sid_123", createdAt: Math.floor(Date.now() / 1000) }
    };

    const [err, result] = await (authClient as any).getTokenSet(session, {
      audience: undefined,
      scope: null
    });

    expect(err).toBeDefined();
    expect(err.name).toBe("MfaRequiredError");
    // Empty mfa_token signals re-auth is needed
    expect(err.mfa_token).toBe("");
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 10. token-set-helpers — normalizeExpiresAt edge paths
// ---------------------------------------------------------------------------

describe("normalizeExpiresAt — edge cases", () => {
  it("returns undefined for empty string", () => {
    expect(normalizeExpiresAt("")).toBeUndefined();
    expect(normalizeExpiresAt("   ")).toBeUndefined();
  });

  it("returns undefined for non-numeric string", () => {
    expect(normalizeExpiresAt("not-a-number")).toBeUndefined();
    expect(normalizeExpiresAt("NaN")).toBeUndefined();
  });

  it("returns undefined for null and undefined", () => {
    expect(normalizeExpiresAt(null)).toBeUndefined();
    expect(normalizeExpiresAt(undefined)).toBeUndefined();
  });

  it("returns the number for a valid numeric string", () => {
    expect(normalizeExpiresAt("1700000000")).toBe(1700000000);
  });

  it("returns undefined for Infinity", () => {
    expect(normalizeExpiresAt(Infinity)).toBeUndefined();
    expect(normalizeExpiresAt(NaN)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 11. normalize-session — legacy stateless and stateful session conversion
// ---------------------------------------------------------------------------

describe("normalizeStatelessSession — legacy cookie format", () => {
  it("converts legacy stateless session to new SessionData format", () => {
    // Legacy stateless cookies store a LegacySession in the JWT payload.
    // The LegacySession has a nested `.user` object, plus top-level token fields.
    const legacyCookie = {
      protectedHeader: {
        iat: 1700000000, // legacy flag: iat in protected header
        uat: 1700001000,
        exp: 1700003600,
        alg: "dir",
        enc: "A256GCM"
      },
      payload: {
        // LegacySession shape: user claims nested under "user"
        user: {
          sub: "user_123",
          name: "Test User",
          email: "user@example.com",
          sid: "sid_abc"
        },
        accessToken: "at_legacy",
        accessTokenScope: "openid profile",
        accessTokenExpiresAt: 1700003600,
        idToken: "id_tok_legacy",
        refreshToken: "rt_legacy"
      }
    } as any;

    const result = normalizeStatelessSession(legacyCookie);

    expect(result.user).toBeDefined();
    expect(result.user.sub).toBe("user_123");
    expect(result.tokenSet).toBeDefined();
    expect(result.tokenSet.accessToken).toBe("at_legacy");
    expect(result.tokenSet.idToken).toBe("id_tok_legacy");
    expect(result.tokenSet.refreshToken).toBe("rt_legacy");
    expect(result.tokenSet.scope).toBe("openid profile");
    expect(result.internal).toBeDefined();
    expect(result.internal!.createdAt).toBe(1700000000);
  });

  it("passes through new-format sessions unchanged", () => {
    const modernCookie = {
      protectedHeader: {
        alg: "dir",
        enc: "A256GCM"
        // No iat — modern format
      },
      payload: {
        user: { sub: "user_123" },
        tokenSet: { accessToken: "at_modern", expiresAt: 1700003600 },
        internal: { sid: "sid_abc", createdAt: 1700000000 }
      }
    } as any;

    const result = normalizeStatelessSession(modernCookie);

    expect(result.user.sub).toBe("user_123");
    expect(result.tokenSet.accessToken).toBe("at_modern");
  });
});

describe("normalizeStatefulSession — legacy data format", () => {
  it("converts legacy stateful session to new SessionData format", () => {
    const legacyData = {
      header: {
        iat: 1700000000,
        uat: 1700001000,
        exp: 1700003600
      },
      data: {
        user: { sub: "user_123", sid: "sid_abc" },
        accessToken: "at_legacy",
        accessTokenScope: "openid profile",
        accessTokenExpiresAt: 1700003600,
        idToken: "id_tok_legacy",
        refreshToken: "rt_legacy"
      }
    } as any;

    const result = normalizeStatefulSession(legacyData);

    expect(result.user.sub).toBe("user_123");
    expect(result.tokenSet.accessToken).toBe("at_legacy");
    expect(result.internal!.createdAt).toBe(1700000000);
  });

  it("passes through modern stateful session data unchanged", () => {
    const modernData = {
      user: { sub: "user_123" },
      tokenSet: { accessToken: "at_modern", expiresAt: 1700003600 },
      internal: { sid: "sid_abc", createdAt: 1700000000 }
    } as any;

    const result = normalizeStatefulSession(modernData);

    expect(result.user.sub).toBe("user_123");
    expect(result.tokenSet.accessToken).toBe("at_modern");
  });
});

// ---------------------------------------------------------------------------
// 12. discovery-cache — JWKS LRU eviction when maxEntries is exceeded
// ---------------------------------------------------------------------------

describe("DiscoveryCache — JWKS LRU eviction", () => {
  it("evicts the oldest JWKS entry when the cache reaches maxEntries", () => {
    const cache = new DiscoveryCache({ maxEntries: 2 });

    const jwks1 = cache.getJwksCacheForUri(
      "https://a.auth0.com/.well-known/jwks.json"
    );
    (jwks1 as any)["test"] = "a";

    const jwks2 = cache.getJwksCacheForUri(
      "https://b.auth0.com/.well-known/jwks.json"
    );
    (jwks2 as any)["test"] = "b";

    // Cache is full (2 entries). Adding a third should evict the first ("a").
    const jwks3 = cache.getJwksCacheForUri(
      "https://c.auth0.com/.well-known/jwks.json"
    );
    (jwks3 as any)["test"] = "c";

    // Re-requesting "a" should return a fresh empty entry (it was evicted)
    const jwks1Again = cache.getJwksCacheForUri(
      "https://a.auth0.com/.well-known/jwks.json"
    );
    expect(Object.keys(jwks1Again)).toHaveLength(0);
  });

  it("moves a re-accessed entry to the end (LRU behavior)", () => {
    const cache = new DiscoveryCache({ maxEntries: 2 });

    cache.getJwksCacheForUri("https://a.auth0.com/.well-known/jwks.json");
    cache.getJwksCacheForUri("https://b.auth0.com/.well-known/jwks.json");

    // Re-access 'a' — should now be the most recently used
    const jwksA = cache.getJwksCacheForUri(
      "https://a.auth0.com/.well-known/jwks.json"
    );
    (jwksA as any)["touched"] = true;

    // Add a third entry — should evict 'b' (least recently used), not 'a'
    cache.getJwksCacheForUri("https://c.auth0.com/.well-known/jwks.json");

    // 'a' should still be present (was LRU-refreshed)
    const aAgain = cache.getJwksCacheForUri(
      "https://a.auth0.com/.well-known/jwks.json"
    );
    expect((aAgain as any)["touched"]).toBe(true);

    // 'b' should be evicted — re-accessing gives a fresh empty entry
    const bAgain = cache.getJwksCacheForUri(
      "https://b.auth0.com/.well-known/jwks.json"
    );
    expect(Object.keys(bAgain)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 13. DPoP JKT calculation failure → DPoPError thrown
//
// auth-client.ts wraps jose.exportJWK / jose.calculateJwkThumbprint in a try-catch
// and rethrows as DPoPError(DPOP_JKT_CALCULATION_FAILED).
//
// We cannot spy on ESM exports from `jose`. Instead we pass a non-extractable
// CryptoKey as dpopKeyPair.publicKey — jose.exportJWK throws "Invalid key: must be
// an extractable CryptoKey", which is caught and re-thrown as DPoPError.
// ---------------------------------------------------------------------------

describe("startInteractiveLogin — DPoP JKT calculation failure", () => {
  it("throws DPoPError(DPOP_JKT_CALCULATION_FAILED) when the DPoP public key is invalid", async () => {
    const secret = await generateSecret(32);

    // Pass a plain object instead of a real CryptoKey.
    // jose.exportJWK throws synchronously when given a non-CryptoKey, which is
    // caught by the try-catch in startInteractiveLogin and rethrown as DPoPError.
    const authClient = new AuthClient({
      transactionStore: new TransactionStore({ secret }),
      sessionStore: new StatelessSessionStore({ secret }),
      domain: DOMAIN,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      secret,
      appBaseUrl: APP_BASE_URL,
      routes: getDefaultRoutes(),
      fetch: makeMinimalFetch(),
      // Invalid key pair triggers the catch block at auth-client.ts:844
      dpopKeyPair: { privateKey: {} as CryptoKey, publicKey: {} as CryptoKey }
    });

    const req = new NextRequest(new URL("/auth/login", APP_BASE_URL), {
      method: "GET"
    });

    await expect(
      (authClient as any).startInteractiveLogin({}, req)
    ).rejects.toMatchObject({
      name: "DPoPError",
      code: DPoPErrorCode.DPOP_JKT_CALCULATION_FAILED
    });
  });
});
