import * as jose from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode
} from "../errors/index.js";
import { SessionData, TOKEN_TYPES } from "../types/index.js";
import {
  buildSessionTransferAudience,
  buildSessionTransferRedirectUrl,
  mapSttServerError,
  parseSessionTransferTokenResponse,
  resolveActorFromSession
} from "./session-transfer-helpers.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ALG = "RS256" as const;
let keyPair: jose.GenerateKeyPairResult;

beforeAll(async () => {
  keyPair = await jose.generateKeyPair(ALG);
});

afterAll(() => {});

async function makeIdToken(opts: {
  expiresIn?: string;
  sub?: string;
}): Promise<string> {
  return new jose.SignJWT({})
    .setProtectedHeader({ alg: ALG })
    .setSubject(opts.sub ?? "agent|123")
    .setIssuedAt()
    .setIssuer("https://test.auth0.local/")
    .setAudience("test_client")
    .setExpirationTime(opts.expiresIn ?? "2h")
    .sign(keyPair.privateKey);
}

function makeSession(idToken?: string): SessionData {
  return {
    user: { sub: "agent|123" },
    tokenSet: {
      accessToken: "at_agent",
      idToken,
      expiresAt: Math.floor(Date.now() / 1000) + 3600
    },
    internal: {
      sid: "sid_123",
      createdAt: Math.floor(Date.now() / 1000)
    }
  };
}

// ---------------------------------------------------------------------------
// 1: buildSessionTransferAudience
// ---------------------------------------------------------------------------

describe("buildSessionTransferAudience", () => {
  it("should build the correct STT audience URN for a given domain", () => {
    const audience = buildSessionTransferAudience("example.us.auth0.com");
    expect(audience).toBe("urn:example.us.auth0.com:session_transfer");
  });

  it("should use the exact domain string passed in", () => {
    const audience = buildSessionTransferAudience("myapp.auth0.com");
    expect(audience).toBe("urn:myapp.auth0.com:session_transfer");
  });

  it("should handle custom domain strings", () => {
    const audience = buildSessionTransferAudience("auth.northwind.com");
    expect(audience).toBe("urn:auth.northwind.com:session_transfer");
  });
});

// ---------------------------------------------------------------------------
// 2: resolveActorFromSession
// ---------------------------------------------------------------------------

describe("resolveActorFromSession", () => {
  describe("explicit actor override", () => {
    it("should return the explicit actor when provided", async () => {
      const idToken = await makeIdToken({});
      const session = makeSession(idToken);
      const [error, actor] = resolveActorFromSession(session, {
        token: "explicit-token",
        type: TOKEN_TYPES.ID_TOKEN
      });

      expect(error).toBeNull();
      expect(actor?.token).toBe("explicit-token");
      expect(actor?.type).toBe(TOKEN_TYPES.ID_TOKEN);
    });

    it("should return the explicit actor even when session has no ID token", () => {
      const session = makeSession(undefined);
      const [error, actor] = resolveActorFromSession(session, {
        token: "explicit-fallback",
        type: TOKEN_TYPES.ID_TOKEN
      });

      expect(error).toBeNull();
      expect(actor?.token).toBe("explicit-fallback");
    });

    it("should return ACTOR_UNAVAILABLE when explicit actor token is empty", () => {
      const session = makeSession(undefined);
      const [error, actor] = resolveActorFromSession(session, {
        token: "",
        type: TOKEN_TYPES.ID_TOKEN
      });

      expect(error).not.toBeNull();
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE);
      expect(actor).toBeNull();
    });

    it("should return ACTOR_UNAVAILABLE when explicit actor token is whitespace", () => {
      const [error, actor] = resolveActorFromSession(null, {
        token: "   ",
        type: TOKEN_TYPES.ID_TOKEN
      });

      expect(error).not.toBeNull();
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE);
      expect(actor).toBeNull();
    });
  });

  describe("session ID token sourcing", () => {
    it("should use the session ID token as the actor when no explicit actor is given", async () => {
      const idToken = await makeIdToken({});
      const session = makeSession(idToken);
      const [error, actor] = resolveActorFromSession(session);

      expect(error).toBeNull();
      expect(actor?.token).toBe(idToken);
      expect(actor?.type).toBe(TOKEN_TYPES.ID_TOKEN);
    });

    it("should return ACTOR_UNAVAILABLE when session has no ID token", () => {
      const session = makeSession(undefined);
      const [error, actor] = resolveActorFromSession(session);

      expect(error).not.toBeNull();
      expect(error).toBeInstanceOf(CustomTokenExchangeError);
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE);
      expect(error?.message).toContain("no ID token");
      expect(actor).toBeNull();
    });

    it("should return ACTOR_UNAVAILABLE when session is null", () => {
      const [error, actor] = resolveActorFromSession(null);

      expect(error).not.toBeNull();
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE);
      expect(actor).toBeNull();
    });

    it("should return ACTOR_UNAVAILABLE when session ID token has expired", async () => {
      // Sign with a negative expiry so it is already expired
      const expiredToken = await new jose.SignJWT({})
        .setProtectedHeader({ alg: ALG })
        .setSubject("agent|expired")
        .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
        .setIssuer("https://test.auth0.local/")
        .setAudience("test_client")
        .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
        .sign(keyPair.privateKey);

      const session = makeSession(expiredToken);
      const [error, actor] = resolveActorFromSession(session);

      expect(error).not.toBeNull();
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE);
      expect(error?.message).toContain("expired");
      expect(actor).toBeNull();
    });

    it("should return ACTOR_UNAVAILABLE when session ID token is malformed", () => {
      const session = makeSession("not.a.valid.jwt");
      const [error, actor] = resolveActorFromSession(session);

      expect(error).not.toBeNull();
      expect(error?.code).toBe(CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE);
      expect(actor).toBeNull();
    });

    it("should accept a valid non-expired session ID token", async () => {
      const idToken = await makeIdToken({ expiresIn: "1h" });
      const session = makeSession(idToken);
      const [error, actor] = resolveActorFromSession(session);

      expect(error).toBeNull();
      expect(actor?.token).toBe(idToken);
      expect(actor?.type).toBe(TOKEN_TYPES.ID_TOKEN);
    });
  });
});

// ---------------------------------------------------------------------------
// 3: buildSessionTransferRedirectUrl
// ---------------------------------------------------------------------------

describe("buildSessionTransferRedirectUrl", () => {
  it("should build a redirect URL for an https target", () => {
    const url = buildSessionTransferRedirectUrl(
      "https://app.example.com/auth/login",
      "stt_abc"
    );

    expect(url).toBe(
      "https://app.example.com/auth/login?session_transfer_token=stt_abc"
    );
  });

  it("should allow http for localhost", () => {
    const url = buildSessionTransferRedirectUrl(
      "http://localhost:3000/auth/login",
      "stt_abc"
    );

    expect(url).toContain("session_transfer_token=stt_abc");
  });

  it("should allow http for 127.0.0.1", () => {
    const url = buildSessionTransferRedirectUrl(
      "http://127.0.0.1:3000/auth/login",
      "stt_abc"
    );

    expect(url).toContain("session_transfer_token=stt_abc");
  });

  it("should allow http for the [::1] IPv6 loopback address", () => {
    const url = buildSessionTransferRedirectUrl(
      "http://[::1]:3000/auth/login",
      "stt_abc"
    );

    expect(url).toContain("session_transfer_token=stt_abc");
  });

  it("should reject a non-loopback http target", () => {
    expect(() =>
      buildSessionTransferRedirectUrl(
        "http://app.example.com/auth/login",
        "stt_abc"
      )
    ).toThrow(CustomTokenExchangeError);
    expect(() =>
      buildSessionTransferRedirectUrl(
        "http://app.example.com/auth/login",
        "stt_abc"
      )
    ).toThrow(/must use https/);
  });

  it("should reject a javascript: scheme target", () => {
    expect(() =>
      buildSessionTransferRedirectUrl("javascript:alert(1)", "stt_abc")
    ).toThrow(CustomTokenExchangeError);
  });

  it("should reject a data: scheme target", () => {
    expect(() =>
      buildSessionTransferRedirectUrl(
        "data:text/html,<script></script>",
        "stt_abc"
      )
    ).toThrow(CustomTokenExchangeError);
  });

  it("should reject a non-absolute URL", () => {
    expect(() =>
      buildSessionTransferRedirectUrl("/auth/login", "stt_abc")
    ).toThrow(CustomTokenExchangeError);
    expect(() =>
      buildSessionTransferRedirectUrl("/auth/login", "stt_abc")
    ).toThrow(/not an absolute URL/);
  });

  it("should reject a malformed URL", () => {
    expect(() =>
      buildSessionTransferRedirectUrl("not a url at all", "stt_abc")
    ).toThrow(CustomTokenExchangeError);
  });

  it("should throw CustomTokenExchangeError with EXCHANGE_FAILED code on rejection", () => {
    try {
      buildSessionTransferRedirectUrl(
        "http://app.example.com/auth/login",
        "stt_abc"
      );
      expect.fail("expected buildSessionTransferRedirectUrl to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(CustomTokenExchangeError);
      expect((err as CustomTokenExchangeError).code).toBe(
        CustomTokenExchangeErrorCode.EXCHANGE_FAILED
      );
    }
  });

  it("should append organization when provided", () => {
    const url = buildSessionTransferRedirectUrl(
      "https://app.example.com/auth/login",
      "stt_abc",
      { organization: "org_globex" }
    );

    expect(url).toContain("organization=org_globex");
  });

  it("should not append organization when not provided", () => {
    const url = buildSessionTransferRedirectUrl(
      "https://app.example.com/auth/login",
      "stt_abc"
    );

    expect(url).not.toContain("organization");
  });

  it("should preserve an existing query string on the target URL", () => {
    const url = buildSessionTransferRedirectUrl(
      "https://app.example.com/auth/login?returnTo=/home",
      "stt_abc"
    );

    expect(url).toContain("returnTo=%2Fhome");
    expect(url).toContain("session_transfer_token=stt_abc");
  });
});

// ---------------------------------------------------------------------------
// 4: parseSessionTransferTokenResponse
// ---------------------------------------------------------------------------

describe("parseSessionTransferTokenResponse", () => {
  it("should map raw token endpoint fields to camelCase result", () => {
    const result = parseSessionTransferTokenResponse({
      access_token: "stt_opaque_token_abc",
      issued_token_type:
        "urn:auth0:params:oauth:token-type:session_transfer_token",
      expires_in: 60,
      token_type: "N_A"
    });

    expect(result.sessionTransferToken).toBe("stt_opaque_token_abc");
    expect(result.issuedTokenType).toBe(
      "urn:auth0:params:oauth:token-type:session_transfer_token"
    );
    expect(result.expiresIn).toBe(60);
    expect(result.tokenType).toBe("N_A");
  });

  it("should leave expiresIn undefined when absent", () => {
    const result = parseSessionTransferTokenResponse({
      access_token: "stt_abc",
      issued_token_type: TOKEN_TYPES.SESSION_TRANSFER_TOKEN
    });

    expect(result.expiresIn).toBeUndefined();
  });

  it("should leave tokenType undefined when absent", () => {
    const result = parseSessionTransferTokenResponse({
      access_token: "stt_abc",
      issued_token_type: TOKEN_TYPES.SESSION_TRANSFER_TOKEN
    });

    expect(result.tokenType).toBeUndefined();
  });

  it("should not include any access_token field under that name", () => {
    const result = parseSessionTransferTokenResponse({
      access_token: "stt_abc",
      issued_token_type: TOKEN_TYPES.SESSION_TRANSFER_TOKEN,
      expires_in: 60
    });

    expect(result).not.toHaveProperty("access_token");
    expect(result).not.toHaveProperty("issued_token_type");
  });

  it("should match the SESSION_TRANSFER_TOKEN constant", () => {
    const result = parseSessionTransferTokenResponse({
      access_token: "stt_xyz",
      issued_token_type: TOKEN_TYPES.SESSION_TRANSFER_TOKEN,
      expires_in: 60
    });

    expect(result.issuedTokenType).toBe(TOKEN_TYPES.SESSION_TRANSFER_TOKEN);
  });
});

// ---------------------------------------------------------------------------
// 5: mapSttServerError
// ---------------------------------------------------------------------------

describe("mapSttServerError", () => {
  it("should map setactor_required to SETACTOR_REQUIRED", () => {
    expect(mapSttServerError("setactor_required")).toBe(
      CustomTokenExchangeErrorCode.SETACTOR_REQUIRED
    );
  });

  it("should return null for codes that merely contain setactor but are not the exact code", () => {
    expect(mapSttServerError("SETACTOR_IS_REQUIRED")).toBeNull();
  });

  it("should map session_transfer_disabled to SESSION_TRANSFER_DISABLED", () => {
    expect(mapSttServerError("session_transfer_disabled")).toBe(
      CustomTokenExchangeErrorCode.SESSION_TRANSFER_DISABLED
    );
  });

  it("should return null for codes that merely contain session_transfer but are not the exact code", () => {
    expect(
      mapSttServerError("Session_Transfer_Tokens_Cannot_Be_Requested")
    ).toBeNull();
  });

  it("should return null for unrelated error codes", () => {
    expect(mapSttServerError("invalid_grant")).toBeNull();
    expect(mapSttServerError("server_error")).toBeNull();
    expect(mapSttServerError("unknown_error")).toBeNull();
  });

  // Per the SDK requirements, the SDK keys off the machine `error` code only and does
  // NOT remap based on `error_description` text. Today the server returns a generic
  // `invalid_request` for these failures, so they fall through to EXCHANGE_FAILED
  // (with the raw message surfaced); the mapping fires the day Auth0 emits a
  // machine-readable code.
  it("should return null for the generic invalid_request the server sends today", () => {
    expect(mapSttServerError("invalid_request")).toBeNull();
  });
});
