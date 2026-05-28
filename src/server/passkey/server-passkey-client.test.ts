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
import { AuthClientProvider } from "../auth-client-provider.js";
import { AuthClient } from "../auth-client.js";
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
  authSession: "test-auth-session-token"
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

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------

describe("ServerPasskeyClient.register()", () => {
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

    const result = await (await makePasskeyClient()).register();

    expect(result.authSession).toBe(DEFAULT.authSession);
    expect(result.authnParamsPublicKey).toEqual({ challenge: "abc123" });
  });

  it("passes user_profile fields in request body", async () => {
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
    ).register({
      email: "jane@example.com",
      name: "Jane Doe"
    });

    expect(capturedBody.user_profile).toMatchObject({
      email: "jane@example.com",
      name: "Jane Doe"
    });
  });

  it("throws PasskeyRegisterError on Auth0 failure", async () => {
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

    await expect((await makePasskeyClient()).register()).rejects.toMatchObject({
      name: "PasskeyRegisterError",
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
      new URL("/api/passkey/register", DEFAULT.appBaseUrl),
      { method: "POST" }
    );

    const result = await (await makePasskeyClient()).register(req);

    expect(result.authSession).toBe(DEFAULT.authSession);
    expect(vi.mocked(cookies)).not.toHaveBeenCalled();
  });

  it("sends realm when connection option is provided", async () => {
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
    ).register({
      email: "jane@example.com",
      connection: "Username-Password-Authentication"
    });

    expect(capturedBody.realm).toBe("Username-Password-Authentication");
  });

  it("sends phone_number in user_profile when phoneNumber is provided", async () => {
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

    await (await makePasskeyClient()).register({ phoneNumber: "+1234567890" });

    expect(capturedBody.user_profile.phone_number).toBe("+1234567890");
  });

  it("sends username in user_profile when username is provided", async () => {
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

    await (await makePasskeyClient()).register({ username: "janedoe" });

    expect(capturedBody.user_profile.username).toBe("janedoe");
  });

  it("throws PasskeyRegisterError when Auth0 rejects unknown user_profile field", async () => {
    server.use(
      http.post(`https://${DEFAULT.domain}/passkey/register`, () =>
        HttpResponse.json(
          {
            error: "invalid_request",
            error_description: "Unknown user_profile field."
          },
          { status: 400 }
        )
      )
    );

    await expect(
      (await makePasskeyClient()).register({ email: "jane@example.com" })
    ).rejects.toMatchObject({
      name: "PasskeyRegisterError",
      error: "invalid_request"
    });
  });
});

// ---------------------------------------------------------------------------
// challenge
// ---------------------------------------------------------------------------

describe("ServerPasskeyClient.challenge()", () => {
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

    const result = await (await makePasskeyClient()).challenge();

    expect(result.authSession).toBe(DEFAULT.authSession);
    expect(result.authnParamsPublicKey).toEqual({
      challenge: "login-challenge"
    });
  });

  it("throws PasskeyChallengeError on Auth0 failure", async () => {
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

    await expect((await makePasskeyClient()).challenge()).rejects.toMatchObject(
      {
        name: "PasskeyChallengeError",
        error: "passkeys_not_enabled"
      }
    );
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
      new URL("/api/passkey/challenge", DEFAULT.appBaseUrl),
      { method: "POST" }
    );

    await (await makePasskeyClient()).challenge(req);

    expect(vi.mocked(cookies)).not.toHaveBeenCalled();
  });

  it("sends realm when connection option is provided", async () => {
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
    ).challenge({
      connection: "Username-Password-Authentication"
    });

    expect(capturedBody.realm).toBe("Username-Password-Authentication");
  });

  it("throws PasskeyChallengeError when no passkey found for user", async () => {
    server.use(
      http.post(`https://${DEFAULT.domain}/passkey/challenge`, () =>
        HttpResponse.json(
          {
            error: "no_passkey_found",
            error_description: "No passkey registered for this user."
          },
          { status: 400 }
        )
      )
    );

    await expect((await makePasskeyClient()).challenge()).rejects.toMatchObject(
      {
        name: "PasskeyChallengeError",
        error: "no_passkey_found"
      }
    );
  });
});

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

describe("ServerPasskeyClient.getToken()", () => {
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
    ).getToken({
      authSession: DEFAULT.authSession,
      authResponse: MOCK_AUTH_RESPONSE
    });

    const setCookie = mockCookieHeaders.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie).toMatch(/__session=/);
  });

  it("throws PasskeyGetTokenError on token exchange failure", async () => {
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
      (await makePasskeyClient()).getToken({
        authSession: DEFAULT.authSession,
        authResponse: MOCK_AUTH_RESPONSE
      })
    ).rejects.toMatchObject({
      name: "PasskeyGetTokenError",
      error: "invalid_grant"
    });

    expect(mockCookieHeaders.get("set-cookie")).toBeNull();
  });

  it("throws TypeError when extra arguments passed (App Router guard)", async () => {
    await expect(
      ((await makePasskeyClient()).getToken as any)(
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
        new URL("/api/passkey/get-token", DEFAULT.appBaseUrl),
        { method: "POST" }
      );
      const res = new NextResponse();

      await (
        await makePasskeyClient()
      ).getToken(req, res, {
        authSession: DEFAULT.authSession,
        authResponse: MOCK_AUTH_RESPONSE
      });

      expect(res.headers.get("set-cookie")).toBeTruthy();
      expect(vi.mocked(cookies)).not.toHaveBeenCalled();
    });

    it("throws TypeError when res is missing", async () => {
      const req = new NextRequest(
        new URL("/api/passkey/get-token", DEFAULT.appBaseUrl),
        { method: "POST" }
      );

      await expect(
        ((await makePasskeyClient()).getToken as any)(req, {
          authSession: DEFAULT.authSession,
          authResponse: MOCK_AUTH_RESPONSE
        })
      ).rejects.toThrow(TypeError);
    });
  });

  it("sends GRANT_TYPE_PASSKEY grant type in token request", async () => {
    let capturedBody: any = null;
    const idToken = await makeIdToken();

    server.use(
      http.post(
        `https://${DEFAULT.domain}/oauth/token`,
        async ({ request }) => {
          capturedBody = await request.json();
          return HttpResponse.json({
            access_token: "new-access-token",
            token_type: "Bearer",
            expires_in: 86400,
            scope: "openid profile email",
            id_token: idToken
          });
        }
      )
    );

    await (
      await makePasskeyClient()
    ).getToken({
      authSession: DEFAULT.authSession,
      authResponse: MOCK_AUTH_RESPONSE
    });

    expect(capturedBody).not.toBeNull();
    expect(capturedBody["grant_type"]).toBe(
      "urn:okta:params:oauth:grant-type:webauthn"
    );
  });

  it("stores id_token claims (email, name) in session after verify", async () => {
    const idToken = await makeIdToken({
      email: "jane@example.com",
      name: "Jane Doe"
    });

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
    ).getToken({
      authSession: DEFAULT.authSession,
      authResponse: MOCK_AUTH_RESPONSE
    });

    const setCookie = mockCookieHeaders.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie).toMatch(/__session=/);
  });

  it("throws PasskeyGetTokenError when id_token is missing from response", async () => {
    server.use(
      http.post(`https://${DEFAULT.domain}/oauth/token`, () =>
        HttpResponse.json({
          access_token: "access-only",
          token_type: "Bearer",
          expires_in: 86400,
          scope: "openid profile email"
        })
      )
    );

    await expect(
      (await makePasskeyClient()).getToken({
        authSession: DEFAULT.authSession,
        authResponse: MOCK_AUTH_RESPONSE
      })
    ).rejects.toThrow();
  });
});
