import { NextRequest, NextResponse } from "next/server.js";
import { ResponseCookies } from "@edge-runtime/cookies";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createAuthorizationServerMetadata,
  getDefaultRoutes,
  setupMswLifecycle
} from "../../test/defaults.js";
import type { SessionData } from "../../types/index.js";
import { encryptMfaToken } from "../../utils/mfa-utils.js";
import { AuthClientProvider } from "../auth-client-provider.js";
import { AuthClient } from "../auth-client.js";
import { encrypt } from "../cookies.js";
import { StatelessSessionStore } from "../session/stateless-session-store.js";
import { TransactionStore } from "../transaction-store.js";
import { ServerMfaClient } from "./server-mfa-client.js";

// ─── Module-level next/headers mock ────────────────────────────────────────
let mockCookieHeaders: Headers;

vi.mock("next/headers.js", () => ({
  cookies: vi.fn(async () => new ResponseCookies(mockCookieHeaders)),
  headers: vi.fn(() => new Headers())
}));

// ─── Constants ──────────────────────────────────────────────────────────────
const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  secret: "test-secret-long-enough-for-hs256-algorithm",
  rawMfaToken: "raw-mfa-token-from-auth0",
  sub: "auth0|test-user-id"
};

let keyPair: jose.GenerateKeyPairResult;

const authorizationServerMetadata = createAuthorizationServerMetadata(
  DEFAULT.domain
);

const server = setupServer(
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json(authorizationServerMetadata)
  ),
  http.get(`https://${DEFAULT.domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({
      keys: [{ ...jwk, kid: "test-key-1", alg: "RS256", use: "sig" }]
    });
  })
);

setupMswLifecycle(server);

beforeAll(async () => {
  keyPair = await jose.generateKeyPair("RS256");
});

// ─── Factory ────────────────────────────────────────────────────────────────
function makeMfaClient(): ServerMfaClient {
  return new ServerMfaClient({
    forRequest: async () =>
      new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: DEFAULT.secret,
        transactionStore: new TransactionStore({ secret: DEFAULT.secret }),
        sessionStore: new StatelessSessionStore({ secret: DEFAULT.secret }),
        routes: getDefaultRoutes()
      }),
    isResolverMode: false
  } as unknown as AuthClientProvider);
}

async function makeEncryptedToken(
  mfaRequirements?: Record<string, any>
): Promise<string> {
  return encryptMfaToken(
    DEFAULT.rawMfaToken,
    "",
    "openid profile",
    mfaRequirements,
    DEFAULT.secret,
    300
  );
}

async function makeSessionCookie(
  overrides: Partial<SessionData> = {}
): Promise<string> {
  const maxAge = 60 * 60;
  const expiration = Math.floor(Date.now() / 1000 + maxAge);
  const session: SessionData = {
    user: { sub: DEFAULT.sub },
    tokenSet: {
      idToken: "id-token",
      accessToken: "old-access-token",
      refreshToken: "refresh-token",
      expiresAt: expiration
    },
    internal: {
      sid: "session-id",
      createdAt: Math.floor(Date.now() / 1000)
    },
    ...overrides
  };
  return encrypt(session, DEFAULT.secret, expiration);
}

// ─── getAuthenticators — camelCase mapping ───────────────────────────────────
describe("ServerMfaClient.getAuthenticators()", () => {
  it("maps snake_case API response to camelCase SDK format", async () => {
    const encryptedToken = await makeEncryptedToken({
      challenge: [{ type: "otp" }]
    });

    server.use(
      http.get(`https://${DEFAULT.domain}/mfa/authenticators`, () =>
        HttpResponse.json([
          {
            id: "auth_123",
            authenticator_type: "otp",
            type: "otp",
            active: true,
            name: "Google Authenticator",
            created_at: "2024-01-01T00:00:00.000Z",
            last_auth: "2024-01-15T00:00:00.000Z"
          }
        ])
      )
    );

    const result = await makeMfaClient().getAuthenticators({
      mfaToken: encryptedToken
    });

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      id: "auth_123",
      authenticatorType: "otp",
      type: "otp",
      active: true,
      name: "Google Authenticator",
      createdAt: "2024-01-01T00:00:00.000Z",
      lastAuthenticatedAt: "2024-01-15T00:00:00.000Z"
    });
  });

  it("maps oob authenticator fields including oobChannel and phoneNumber", async () => {
    const encryptedToken = await makeEncryptedToken({
      challenge: [{ type: "oob" }]
    });

    server.use(
      http.get(`https://${DEFAULT.domain}/mfa/authenticators`, () =>
        HttpResponse.json([
          {
            id: "auth_456",
            authenticator_type: "oob",
            type: "oob",
            active: true,
            oob_channel: "sms",
            phone_number: "+1***5678"
          }
        ])
      )
    );

    const result = await makeMfaClient().getAuthenticators({
      mfaToken: encryptedToken
    });

    expect(result[0]).toMatchObject({
      authenticatorType: "oob",
      oobChannel: "sms",
      phoneNumber: "+1***5678"
    });
  });
});

// ─── challenge() ─────────────────────────────────────────────────────────────
describe("ServerMfaClient.challenge()", () => {
  beforeEach(() => {
    mockCookieHeaders = new Headers();
  });

  it("returns camelCase challenge response for OTP", async () => {
    const encryptedToken = await makeEncryptedToken({
      challenge: [{ type: "otp" }]
    });

    server.use(
      http.post(`https://${DEFAULT.domain}/mfa/challenge`, () =>
        HttpResponse.json({ challenge_type: "otp" })
      )
    );

    const result = await makeMfaClient().challenge({
      mfaToken: encryptedToken,
      challengeType: "otp"
    });

    expect(result).toMatchObject({ challengeType: "otp" });
  });

  it("returns camelCase challenge response for OOB with oobCode and bindingMethod", async () => {
    const encryptedToken = await makeEncryptedToken({
      challenge: [{ type: "oob" }]
    });

    server.use(
      http.post(`https://${DEFAULT.domain}/mfa/challenge`, () =>
        HttpResponse.json({
          challenge_type: "oob",
          oob_code: "oob_abc123",
          binding_method: "prompt"
        })
      )
    );

    const result = await makeMfaClient().challenge({
      mfaToken: encryptedToken,
      challengeType: "oob"
    });

    expect(result).toMatchObject({
      challengeType: "oob",
      oobCode: "oob_abc123",
      bindingMethod: "prompt"
    });
  });

  it("sends authenticatorId in the request body when provided", async () => {
    const encryptedToken = await makeEncryptedToken({
      challenge: [{ type: "otp" }]
    });

    let capturedBody: any;
    server.use(
      http.post(
        `https://${DEFAULT.domain}/mfa/challenge`,
        async ({ request }) => {
          capturedBody = await request.json();
          return HttpResponse.json({ challenge_type: "otp" });
        }
      )
    );

    await makeMfaClient().challenge({
      mfaToken: encryptedToken,
      challengeType: "otp",
      authenticatorId: "auth_123"
    });

    expect(capturedBody).toMatchObject({ authenticator_id: "auth_123" });
  });

  it("throws when challenge type is not in mfaRequirements", async () => {
    const encryptedToken = await makeEncryptedToken({
      challenge: [{ type: "otp" }]
    });

    await expect(
      makeMfaClient().challenge({
        mfaToken: encryptedToken,
        challengeType: "oob"
      })
    ).rejects.toMatchObject({ code: "mfa_no_available_factors" });
  });

  it("allows any challenge type when mfaRequirements is absent", async () => {
    const encryptedToken = await makeEncryptedToken(undefined);

    server.use(
      http.post(`https://${DEFAULT.domain}/mfa/challenge`, () =>
        HttpResponse.json({ challenge_type: "otp" })
      )
    );

    const result = await makeMfaClient().challenge({
      mfaToken: encryptedToken,
      challengeType: "otp"
    });

    expect(result.challengeType).toBe("otp");
  });
});

// ─── enroll() — authenticatorTypes format ────────────────────────────────────
describe("ServerMfaClient.enroll() — authenticatorTypes", () => {
  beforeEach(() => {
    mockCookieHeaders = new Headers();
  });

  it("returns camelCase enrollment response for OTP", async () => {
    const encryptedToken = await makeEncryptedToken();

    server.use(
      http.post(`https://${DEFAULT.domain}/mfa/associate`, () =>
        HttpResponse.json({
          authenticator_type: "otp",
          barcode_uri: "otpauth://totp/example",
          secret: "BASE32SECRET"
        })
      )
    );

    const result = await makeMfaClient().enroll({
      mfaToken: encryptedToken,
      authenticatorTypes: ["otp"]
    });

    expect(result).toMatchObject({
      authenticatorType: "otp",
      barcodeUri: "otpauth://totp/example",
      secret: "BASE32SECRET"
    });
  });

  it("returns camelCase enrollment response for OOB SMS", async () => {
    const encryptedToken = await makeEncryptedToken();

    server.use(
      http.post(`https://${DEFAULT.domain}/mfa/associate`, () =>
        HttpResponse.json({
          authenticator_type: "oob",
          oob_channel: "sms",
          oob_code: "oob_xyz"
        })
      )
    );

    const result = await makeMfaClient().enroll({
      mfaToken: encryptedToken,
      authenticatorTypes: ["oob"],
      oobChannels: ["sms"],
      phoneNumber: "+15551234567"
    });

    expect(result).toMatchObject({
      authenticatorType: "oob",
      oobChannel: "sms",
      oobCode: "oob_xyz"
    });
  });

  it("includes recoveryCodes when Auth0 returns them", async () => {
    const encryptedToken = await makeEncryptedToken();

    server.use(
      http.post(`https://${DEFAULT.domain}/mfa/associate`, () =>
        HttpResponse.json({
          authenticator_type: "otp",
          barcode_uri: "otpauth://totp/example",
          secret: "BASE32SECRET",
          recovery_codes: ["code-1", "code-2"]
        })
      )
    );

    const result = await makeMfaClient().enroll({
      mfaToken: encryptedToken,
      authenticatorTypes: ["otp"]
    });

    expect(result).toMatchObject({
      recoveryCodes: ["code-1", "code-2"]
    });
  });

  it("throws on Auth0 400 error", async () => {
    const encryptedToken = await makeEncryptedToken();

    server.use(
      http.post(`https://${DEFAULT.domain}/mfa/associate`, () =>
        HttpResponse.json(
          {
            error: "invalid_request",
            error_description: "Invalid authenticator type"
          },
          { status: 400 }
        )
      )
    );

    await expect(
      makeMfaClient().enroll({
        mfaToken: encryptedToken,
        authenticatorTypes: ["invalid" as any]
      })
    ).rejects.toMatchObject({ code: "invalid_request" });
  });
});

// ─── enroll() — factorType format (normalizeEnrollOptions passthrough) ────────
describe("ServerMfaClient.enroll() — factorType", () => {
  it("normalizes factorType:otp to authenticatorTypes:[otp]", async () => {
    const encryptedToken = await makeEncryptedToken();

    let capturedBody: any;
    server.use(
      http.post(
        `https://${DEFAULT.domain}/mfa/associate`,
        async ({ request }) => {
          capturedBody = await request.json();
          return HttpResponse.json({
            authenticator_type: "otp",
            barcode_uri: "otpauth://totp/example",
            secret: "BASE32SECRET"
          });
        }
      )
    );

    await makeMfaClient().enroll({
      mfaToken: encryptedToken,
      factorType: "otp"
    });

    expect(capturedBody).toMatchObject({
      authenticator_types: ["otp"]
    });
  });

  it("normalizes factorType:sms to oob with sms channel", async () => {
    const encryptedToken = await makeEncryptedToken();

    let capturedBody: any;
    server.use(
      http.post(
        `https://${DEFAULT.domain}/mfa/associate`,
        async ({ request }) => {
          capturedBody = await request.json();
          return HttpResponse.json({
            authenticator_type: "oob",
            oob_channel: "sms",
            oob_code: "oob_xyz"
          });
        }
      )
    );

    await makeMfaClient().enroll({
      mfaToken: encryptedToken,
      factorType: "sms",
      phoneNumber: "+15551234567"
    });

    expect(capturedBody).toMatchObject({
      authenticator_types: ["oob"],
      oob_channels: ["sms"],
      phone_number: "+15551234567"
    });
  });

  it("throws InvalidRequestError for unknown factorType", async () => {
    const encryptedToken = await makeEncryptedToken();

    await expect(
      makeMfaClient().enroll({
        mfaToken: encryptedToken,
        factorType: "unknown_type" as any
      })
    ).rejects.toMatchObject({
      message: expect.stringContaining("unknown_type")
    });
  });

  it("throws InvalidRequestError when factorType:sms is missing phoneNumber", async () => {
    const encryptedToken = await makeEncryptedToken();

    await expect(
      makeMfaClient().enroll({
        mfaToken: encryptedToken,
        factorType: "sms"
      } as any)
    ).rejects.toMatchObject({
      message: expect.stringContaining("phoneNumber")
    });
  });
});

// ─── verify() — Pages Router overload argument validation ────────────────────
describe("ServerMfaClient.verify() — argument guards", () => {
  beforeEach(() => {
    mockCookieHeaders = new Headers();
  });

  it("throws TypeError when called with req but missing res and options", async () => {
    const req = new NextRequest(
      new URL("/auth/mfa/verify", DEFAULT.appBaseUrl),
      { method: "POST" }
    );

    await expect(
      (makeMfaClient().verify as any)(req, undefined, undefined)
    ).rejects.toMatchObject({
      message: expect.stringContaining("All three arguments required")
    });
  });

  it("throws TypeError when App Router verify() is called with extra args", async () => {
    const encryptedToken = await makeEncryptedToken();

    await expect(
      (makeMfaClient().verify as any)(
        { mfaToken: encryptedToken, otp: "123456" },
        new NextResponse()
      )
    ).rejects.toMatchObject({
      message: expect.stringContaining("Only one argument allowed")
    });
  });
});

// ─── verify() — Pages Router full flow ───────────────────────────────────────
describe("ServerMfaClient.verify() — Pages Router", () => {
  beforeEach(() => {
    mockCookieHeaders = new Headers();
  });

  it("stores tokens in session cookie on res and returns success:true", async () => {
    const { cookies } = await import("next/headers.js");
    vi.mocked(cookies).mockClear();

    const sessionCookie = await makeSessionCookie();
    const encryptedToken = await makeEncryptedToken({
      challenge: [{ type: "otp" }]
    });

    server.use(
      http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
        HttpResponse.json({
          access_token: "new-access-token",
          token_type: "Bearer",
          expires_in: 3600
        })
      )
    );

    const req = new NextRequest(
      new URL("/auth/mfa/verify", DEFAULT.appBaseUrl),
      {
        method: "POST",
        headers: { cookie: `__session=${sessionCookie}` }
      }
    );
    const res = new NextResponse();

    const result = await makeMfaClient().verify(req, res, {
      mfaToken: encryptedToken,
      otp: "123456"
    });

    expect(result).toEqual({ success: true });
    expect(res.headers.get("set-cookie")).toBeTruthy();
    expect(vi.mocked(cookies)).not.toHaveBeenCalled();
  });

  it("includes recovery_code in result when Auth0 returns one", async () => {
    const sessionCookie = await makeSessionCookie();
    const encryptedToken = await makeEncryptedToken();

    server.use(
      http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
        HttpResponse.json({
          access_token: "new-access-token",
          token_type: "Bearer",
          expires_in: 3600,
          recovery_code: "new-recovery-code"
        })
      )
    );

    const req = new NextRequest(
      new URL("/auth/mfa/verify", DEFAULT.appBaseUrl),
      {
        method: "POST",
        headers: { cookie: `__session=${sessionCookie}` }
      }
    );
    const res = new NextResponse();

    const result = await makeMfaClient().verify(req, res, {
      mfaToken: encryptedToken,
      recoveryCode: "old-recovery-code"
    });

    expect(result).toEqual({
      success: true,
      recovery_code: "new-recovery-code"
    });
  });
});
