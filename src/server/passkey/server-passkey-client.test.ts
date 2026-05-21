/**
 * Unit tests for ServerPasskeyClient — App Router and Pages Router paths.
 *
 * next/headers is mocked at module level so App Router cookie reads/writes
 * can be observed without a real Next.js runtime.
 */
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
import { generateSecret } from "../../test/utils.js";
import { AuthClientProvider } from "../auth-client-provider.js";
import { AuthClient } from "../auth-client.js";
import { encrypt } from "../cookies.js";
import { StatelessSessionStore } from "../session/stateless-session-store.js";
import { TransactionStore } from "../transaction-store.js";
import { ServerPasskeyClient } from "./server-passkey-client.js";

// Shared mutable headers that the mocked next/headers cookies() returns.
let mockCookieHeaders: Headers;

vi.mock("next/headers.js", () => ({
  cookies: vi.fn(async () => new ResponseCookies(mockCookieHeaders)),
  headers: vi.fn(() => new Headers())
}));

const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  sub: "passkeys|test-user-id",
  sid: "test-sid",
  authSession: "test-auth-session-token",
  authenticationMethodId: "am_abc123"
};

const MOCK_AUTH_RESPONSE = {
  id: "cred-id",
  rawId: "cred-raw-id",
  type: "public-key" as const,
  response: {
    clientDataJSON: "clientDataJSON-base64url",
    attestationObject: "attestationObject-base64url"
  }
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

async function makeIdToken(
  claims: Record<string, unknown> = {}
): Promise<string> {
  return new jose.SignJWT({ sub: DEFAULT.sub, sid: DEFAULT.sid, ...claims })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(`https://${DEFAULT.domain}`)
    .setAudience(DEFAULT.clientId)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(keyPair.privateKey);
}

async function makePasskeyClient(
  secret?: string
): Promise<ServerPasskeyClient> {
  const s = secret ?? "test-secret-long-enough-for-hs256-algorithm";
  return new ServerPasskeyClient({
    forRequest: async () =>
      new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: s,
        transactionStore: new TransactionStore({ secret: s }),
        sessionStore: new StatelessSessionStore({ secret: s }),
        routes: getDefaultRoutes()
      }),
    isResolverMode: false
  } as unknown as AuthClientProvider);
}

async function makeSessionCookie(secret: string): Promise<string> {
  const session = {
    user: { sub: DEFAULT.sub },
    tokenSet: {
      accessToken: "existing-access-token",
      refreshToken: "existing-refresh-token",
      idToken: "existing-id-token",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      scope: "openid profile email"
    },
    internal: { sid: DEFAULT.sid, createdAt: Math.floor(Date.now() / 1000) }
  };
  return encrypt(session, secret, Math.floor(Date.now() / 1000) + 3600);
}

/** Mock the token endpoint to return an access token for the me/ audience. */
function mockMeAudienceTokenRefresh() {
  server.use(
    http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
      HttpResponse.json({
        access_token: "me-audience-access-token",
        token_type: "Bearer",
        expires_in: 86400,
        scope: "openid profile email create:me:authentication_methods"
      })
    )
  );
}

// ---------------------------------------------------------------------------
// signupChallenge
// ---------------------------------------------------------------------------

describe("ServerPasskeyClient.signupChallenge()", () => {
  beforeEach(() => {
    mockCookieHeaders = new Headers();
  });

  it("returns challenge response on success (App Router)", async () => {
    server.use(
      http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
        HttpResponse.json({
          auth_session: DEFAULT.authSession,
          authn_params_public_key: { challenge: "abc123" }
        })
      )
    );

    const result = await (await makePasskeyClient()).signupChallenge();

    expect(result.authSession).toBe(DEFAULT.authSession);
    expect(result.authnParamsPublicKey).toEqual({ challenge: "abc123" });
  });

  it("passes userDisplayName in request body", async () => {
    let capturedBody: any;
    server.use(
      http.post(
        `https://${DEFAULT.domain}/passkey/register`,
        async ({ request }) => {
          capturedBody = await request.json();
          return HttpResponse.json({
            auth_session: DEFAULT.authSession,
            authn_params_public_key: {}
          });
        }
      )
    );

    await (
      await makePasskeyClient()
    ).signupChallenge({
      userDisplayName: "Jane Doe"
    });

    expect(capturedBody.user_display_name).toBe("Jane Doe");
  });

  it("throws PasskeySignupChallengeError on Auth0 failure", async () => {
    server.use(
      http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
        HttpResponse.json(
          {
            error: "passkeys_not_enabled",
            error_description: "Passkeys are not enabled for this application."
          },
          { status: 400 }
        )
      )
    );

    await expect(
      (await makePasskeyClient()).signupChallenge()
    ).rejects.toMatchObject({
      name: "PasskeySignupChallengeError",
      error: "passkeys_not_enabled"
    });
  });

  it("returns challenge response via Pages Router overload", async () => {
    const { cookies } = await import("next/headers.js");
    vi.mocked(cookies).mockClear();

    server.use(
      http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
        HttpResponse.json({
          auth_session: DEFAULT.authSession,
          authn_params_public_key: { challenge: "pages-router" }
        })
      )
    );

    const req = new NextRequest(
      new URL("/api/passkey/signup-challenge", DEFAULT.appBaseUrl),
      { method: "POST" }
    );

    const result = await (await makePasskeyClient()).signupChallenge(req);

    expect(result.authSession).toBe(DEFAULT.authSession);
    expect(vi.mocked(cookies)).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// loginChallenge
// ---------------------------------------------------------------------------

describe("ServerPasskeyClient.loginChallenge()", () => {
  beforeEach(() => {
    mockCookieHeaders = new Headers();
  });

  it("returns challenge response on success (App Router)", async () => {
    server.use(
      http.post(`https://${DEFAULT.domain}/passkey/challenge`, () =>
        HttpResponse.json({
          auth_session: DEFAULT.authSession,
          authn_params_public_key: { challenge: "login-challenge" }
        })
      )
    );

    const result = await (await makePasskeyClient()).loginChallenge();

    expect(result.authSession).toBe(DEFAULT.authSession);
    expect(result.authnParamsPublicKey).toEqual({
      challenge: "login-challenge"
    });
  });

  it("passes username in request body", async () => {
    let capturedBody: any;
    server.use(
      http.post(
        `https://${DEFAULT.domain}/passkey/challenge`,
        async ({ request }) => {
          capturedBody = await request.json();
          return HttpResponse.json({
            auth_session: DEFAULT.authSession,
            authn_params_public_key: {}
          });
        }
      )
    );

    await (
      await makePasskeyClient()
    ).loginChallenge({
      username: "user@example.com"
    });

    expect(capturedBody.username).toBe("user@example.com");
  });

  it("throws PasskeyLoginChallengeError on Auth0 failure", async () => {
    server.use(
      http.post(`https://${DEFAULT.domain}/passkey/challenge`, () =>
        HttpResponse.json(
          {
            error: "passkeys_not_enabled",
            error_description: "Passkeys are not enabled."
          },
          { status: 400 }
        )
      )
    );

    await expect(
      (await makePasskeyClient()).loginChallenge()
    ).rejects.toMatchObject({
      name: "PasskeyLoginChallengeError",
      error: "passkeys_not_enabled"
    });
  });

  it("returns challenge response via Pages Router overload", async () => {
    const { cookies } = await import("next/headers.js");
    vi.mocked(cookies).mockClear();

    server.use(
      http.post(`https://${DEFAULT.domain}/passkey/challenge`, () =>
        HttpResponse.json({
          auth_session: DEFAULT.authSession,
          authn_params_public_key: {}
        })
      )
    );

    const req = new NextRequest(
      new URL("/api/passkey/login-challenge", DEFAULT.appBaseUrl),
      { method: "POST" }
    );

    await (await makePasskeyClient()).loginChallenge(req);

    expect(vi.mocked(cookies)).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

describe("ServerPasskeyClient.verify()", () => {
  beforeEach(() => {
    mockCookieHeaders = new Headers();
  });

  it("writes session cookie to next/headers on success (App Router)", async () => {
    const idToken = await makeIdToken();

    server.use(
      http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
        HttpResponse.json({
          access_token: "new-access-token",
          token_type: "Bearer",
          expires_in: 86400,
          scope: "openid profile email",
          id_token: idToken
        })
      )
    );

    await (
      await makePasskeyClient()
    ).verify({
      authSession: DEFAULT.authSession,
      authResponse: MOCK_AUTH_RESPONSE
    });

    const setCookie = mockCookieHeaders.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie).toMatch(/__session=/);
  });

  it("throws PasskeyVerifyError on token exchange failure", async () => {
    server.use(
      http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
        HttpResponse.json(
          {
            error: "invalid_grant",
            error_description: "Invalid passkey assertion."
          },
          { status: 400 }
        )
      )
    );

    await expect(
      (await makePasskeyClient()).verify({
        authSession: DEFAULT.authSession,
        authResponse: MOCK_AUTH_RESPONSE
      })
    ).rejects.toMatchObject({
      name: "PasskeyVerifyError",
      error: "invalid_grant"
    });

    expect(mockCookieHeaders.get("set-cookie")).toBeNull();
  });

  it("throws TypeError when extra arguments passed (App Router guard)", async () => {
    await expect(
      ((await makePasskeyClient()).verify as any)(
        { authSession: DEFAULT.authSession, authResponse: MOCK_AUTH_RESPONSE },
        new NextResponse()
      )
    ).rejects.toThrow(TypeError);
  });

  describe("Pages Router overload (req, res, options)", () => {
    it("writes session cookie to res and not to next/headers", async () => {
      const { cookies } = await import("next/headers.js");
      vi.mocked(cookies).mockClear();

      const idToken = await makeIdToken();

      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
          HttpResponse.json({
            access_token: "new-access-token",
            token_type: "Bearer",
            expires_in: 86400,
            scope: "openid profile email",
            id_token: idToken
          })
        )
      );

      const req = new NextRequest(
        new URL("/api/passkey/verify", DEFAULT.appBaseUrl),
        { method: "POST" }
      );
      const res = new NextResponse();

      await (
        await makePasskeyClient()
      ).verify(req, res, {
        authSession: DEFAULT.authSession,
        authResponse: MOCK_AUTH_RESPONSE
      });

      expect(res.headers.get("set-cookie")).toBeTruthy();
      expect(vi.mocked(cookies)).not.toHaveBeenCalled();
    });

    it("throws TypeError when res is missing", async () => {
      const req = new NextRequest(
        new URL("/api/passkey/verify", DEFAULT.appBaseUrl),
        { method: "POST" }
      );

      await expect(
        ((await makePasskeyClient()).verify as any)(req, {
          authSession: DEFAULT.authSession,
          authResponse: MOCK_AUTH_RESPONSE
        })
      ).rejects.toThrow(TypeError);
    });
  });
});

// ---------------------------------------------------------------------------
// enrollmentChallenge
// ---------------------------------------------------------------------------

describe("ServerPasskeyClient.enrollmentChallenge()", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
    mockCookieHeaders = new Headers();
  });

  it("returns enrollment challenge when session is present (App Router)", async () => {
    const sessionValue = await makeSessionCookie(secret);
    mockCookieHeaders.set(
      "set-cookie",
      `__session=${sessionValue}; Path=/; HttpOnly`
    );

    mockMeAudienceTokenRefresh();

    server.use(
      http.post(`https://${DEFAULT.domain}/me/v1/authentication-methods`, () =>
        HttpResponse.json(
          {
            auth_session: DEFAULT.authSession,
            authn_params_public_key: { challenge: "enroll-challenge" }
          },
          {
            status: 201,
            headers: {
              location: `/me/v1/authentication-methods/${DEFAULT.authenticationMethodId}`
            }
          }
        )
      )
    );

    const client = new ServerPasskeyClient({
      forRequest: async () =>
        new AuthClient({
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          appBaseUrl: DEFAULT.appBaseUrl,
          secret,
          transactionStore: new TransactionStore({ secret }),
          sessionStore: new StatelessSessionStore({ secret }),
          routes: getDefaultRoutes()
        }),
      isResolverMode: false
    } as unknown as AuthClientProvider);

    const result = await client.enrollmentChallenge();

    expect(result.authenticationMethodId).toBe(DEFAULT.authenticationMethodId);
    expect(result.authSession).toBe(DEFAULT.authSession);
    expect(result.authnParamsPublicKey).toEqual({
      challenge: "enroll-challenge"
    });
  });

  it("throws PasskeyEnrollmentChallengeError when no session", async () => {
    // No session cookie — mockCookieHeaders is empty
    await expect(
      (await makePasskeyClient(secret)).enrollmentChallenge()
    ).rejects.toMatchObject({
      name: "PasskeyEnrollmentChallengeError",
      error: "not_authenticated"
    });
  });
});

// ---------------------------------------------------------------------------
// enrollVerify
// ---------------------------------------------------------------------------

describe("ServerPasskeyClient.enrollVerify()", () => {
  let secret: string;

  beforeEach(async () => {
    secret = await generateSecret(32);
    mockCookieHeaders = new Headers();
  });

  it("returns authentication method on success (App Router)", async () => {
    const sessionValue = await makeSessionCookie(secret);
    mockCookieHeaders.set(
      "set-cookie",
      `__session=${sessionValue}; Path=/; HttpOnly`
    );

    mockMeAudienceTokenRefresh();

    server.use(
      http.post(
        `https://${DEFAULT.domain}/me/v1/authentication-methods/${DEFAULT.authenticationMethodId}/verify`,
        () =>
          HttpResponse.json({
            id: DEFAULT.authenticationMethodId,
            type: "passkey",
            name: "Touch ID",
            created_at: "2024-01-01T00:00:00.000Z",
            last_authenticated_at: "2024-01-01T00:00:00.000Z"
          })
      )
    );

    const client = new ServerPasskeyClient({
      forRequest: async () =>
        new AuthClient({
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          appBaseUrl: DEFAULT.appBaseUrl,
          secret,
          transactionStore: new TransactionStore({ secret }),
          sessionStore: new StatelessSessionStore({ secret }),
          routes: getDefaultRoutes()
        }),
      isResolverMode: false
    } as unknown as AuthClientProvider);

    const result = await client.enrollVerify({
      authenticationMethodId: DEFAULT.authenticationMethodId,
      authSession: DEFAULT.authSession,
      authResponse: MOCK_AUTH_RESPONSE
    });

    expect(result.id).toBe(DEFAULT.authenticationMethodId);
    expect(result.type).toBe("passkey");
    expect(result.name).toBe("Touch ID");
  });

  it("throws PasskeyEnrollVerifyError when no session", async () => {
    await expect(
      (await makePasskeyClient(secret)).enrollVerify({
        authenticationMethodId: DEFAULT.authenticationMethodId,
        authSession: DEFAULT.authSession,
        authResponse: MOCK_AUTH_RESPONSE
      })
    ).rejects.toMatchObject({
      name: "PasskeyEnrollVerifyError",
      error: "not_authenticated"
    });
  });

  it("throws PasskeyEnrollVerifyError on API failure", async () => {
    const sessionValue = await makeSessionCookie(secret);
    mockCookieHeaders.set(
      "set-cookie",
      `__session=${sessionValue}; Path=/; HttpOnly`
    );

    mockMeAudienceTokenRefresh();

    server.use(
      http.post(
        `https://${DEFAULT.domain}/me/v1/authentication-methods/${DEFAULT.authenticationMethodId}/verify`,
        () =>
          HttpResponse.json(
            {
              error: "credential_already_registered",
              error_description: "This passkey is already registered."
            },
            { status: 400 }
          )
      )
    );

    const client = new ServerPasskeyClient({
      forRequest: async () =>
        new AuthClient({
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          appBaseUrl: DEFAULT.appBaseUrl,
          secret,
          transactionStore: new TransactionStore({ secret }),
          sessionStore: new StatelessSessionStore({ secret }),
          routes: getDefaultRoutes()
        }),
      isResolverMode: false
    } as unknown as AuthClientProvider);

    await expect(
      client.enrollVerify({
        authenticationMethodId: DEFAULT.authenticationMethodId,
        authSession: DEFAULT.authSession,
        authResponse: MOCK_AUTH_RESPONSE
      })
    ).rejects.toMatchObject({
      name: "PasskeyEnrollVerifyError",
      error: "credential_already_registered"
    });
  });

  it("throws TypeError when options missing (Pages Router guard)", async () => {
    const req = new NextRequest(
      new URL("/api/passkey/enroll-verify", DEFAULT.appBaseUrl),
      { method: "POST" }
    );

    await expect(
      (await makePasskeyClient(secret)).enrollVerify(req as any)
    ).rejects.toThrow(TypeError);
  });
});
