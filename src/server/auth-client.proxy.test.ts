import { NextRequest, NextResponse } from "next/server.js";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { SessionData } from "../types/index.js";
import { generateDpopKeyPair } from "../utils/dpopUtils.js";
import { AuthClient } from "./auth-client.js";
import { decrypt, encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

const DEFAULT = {
  domain: "test.auth0.local",
  clientId: "client_123",
  clientSecret: "client-secret",
  appBaseUrl: "https://example.com",
  sid: "auth0-sid",
  idToken: "idt_123",
  accessToken: "at_123",
  refreshToken: "rt_123",
  sub: "user_123",
  alg: "RS256",
  keyPair: await jose.generateKeyPair("RS256")
};

describe("Authentication Client", async () => {
  describe("handleMyAccount", async () => {
    const myAccountResponse = {
      branding: {
        logo_url:
          "https://cdn.cookielaw.org/logos/5b38f79c-c925-4d4e-af5e-ec27e97e1068/01963fbf-a156-710c-9ff0-e3528aa88982/baec8c9a-62ca-45e4-8549-18024c4409b1/auth0-logo.png",
        colors: { page_background: "#ffffff", primary: "#007bff" }
      },
      id: "org_HdiNOwdtHO4fuiTU",
      display_name: "cyborg",
      name: "cyborg"
    };

    const secret = await generateSecret(32);
    let authClient: AuthClient;

    // Create MSW server with default handlers
    const server = setupServer(
      // Discovery endpoint
      http.get(
        `https://${DEFAULT.domain}/.well-known/openid-configuration`,
        () => {
          return HttpResponse.json(_authorizationServerMetadata);
        }
      ),
      // OAuth token endpoint
      http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
        const jwt = await new jose.SignJWT({
          sid: DEFAULT.sid,
          auth_time: Date.now(),
          nonce: "nonce-value",
          "https://example.com/custom_claim": "value"
        })
          .setProtectedHeader({ alg: DEFAULT.alg })
          .setSubject(DEFAULT.sub)
          .setIssuedAt()
          .setIssuer(_authorizationServerMetadata.issuer)
          .setAudience(DEFAULT.clientId)
          .setExpirationTime("2h")
          .sign(DEFAULT.keyPair.privateKey);

        return HttpResponse.json({
          token_type: "Bearer",
          access_token: DEFAULT.accessToken,
          refresh_token: DEFAULT.refreshToken,
          id_token: jwt,
          expires_in: 86400 // expires in 10 days
        });
      }),
      // My Account proxy endpoint (default GET)
      http.get(`https://${DEFAULT.domain}/me/v1/foo-bar/12`, ({ request }) => {
        const url = new URL(request.url);
        if (url.searchParams.get("foo") === "bar") {
          return HttpResponse.json(myAccountResponse);
        }
        return new HttpResponse(null, { status: 404 });
      }),
      // My Account proxy endpoint (default POST) - acts as a fallback
      http.post(`https://${DEFAULT.domain}/me/v1/foo-bar/12`, () => {
        return HttpResponse.json(myAccountResponse);
      })
    );

    // Start MSW server before all tests
    beforeAll(() => {
      server.listen({ onUnhandledRequest: "bypass" });
    });

    // Reset handlers after each test
    afterEach(() => {
      server.resetHandlers();
    });

    // Stop MSW server after all tests
    afterAll(() => {
      server.close();
    });

    beforeEach(async () => {
      const dpopKeyPair = await generateDpopKeyPair();
      authClient = new AuthClient({
        transactionStore: new TransactionStore({
          secret
        }),
        sessionStore: new StatelessSessionStore({
          secret
        }),

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        // No need to pass custom fetch - MSW will intercept native fetch
        useDPoP: true,
        dpopKeyPair: dpopKeyPair,
        authorizationParameters: {
          audience: "test-api",
          scope: {
            [`https://${DEFAULT.domain}/me/`]: "foo"
          }
        },
        fetch: (url, init) =>
          fetch(url, { ...init, ...(init?.body ? { duplex: "half" } : {}) })
      });
    });

    it("should return 401 when no session", async () => {
      const request = new NextRequest(
        new URL("/me/foo-bar/12?foo=bar", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            "auth0-scope": "foo:bar"
          }
        }
      );

      const response = await authClient.handleMyAccount(request);
      expect(response.status).toEqual(401);

      const text = await response.text();
      expect(text).toEqual("The user does not have an active session.");
    });

    it("should proxy GET request to my account", async () => {
      const session = createInitialSessionData();

      const cookie = await createSessionCookie(session, secret);

      const request = new NextRequest(
        new URL("/me/foo-bar/12?foo=bar", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "auth0-scope": "foo:bar"
          }
        }
      );

      const response = await authClient.handleMyAccount(request);
      expect(response.status).toEqual(200);

      const json = await response.json();
      expect(json).toEqual(myAccountResponse);
    });

    it("should read from the cache", async () => {
      const cachedAccessToken = "cached_at_123";
      const session = createInitialSessionData({
        accessTokens: [
          {
            audience: `https://${DEFAULT.domain}/me/`,
            accessToken: cachedAccessToken,
            scope: "foo foo:bar",
            token_type: "Bearer",
            expiresAt: Math.floor(Date.now() / 1000) + 3600
          }
        ]
      });
      const cookie = await createSessionCookie(session, secret);

      // Override the handler to check for the cached access token
      server.use(
        http.get(
          `https://${DEFAULT.domain}/me/v1/foo-bar/12`,
          ({ request }) => {
            const authHeader = request.headers.get("authorization");
            const token = authHeader?.split(" ")[1];

            if (token === cachedAccessToken) {
              return HttpResponse.json(myAccountResponse);
            }
            return new HttpResponse(null, { status: 401 });
          }
        )
      );

      const request = new NextRequest(
        new URL("/me/foo-bar/12", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "auth0-scope": "foo:bar"
          }
        }
      );

      const response = await authClient.handleMyAccount(request);

      // The Set Cookie header is not updated since the cache was used
      expect(response.headers.get("Set-Cookie")).toBeFalsy();
    });

    it("should update the cache when using stateless storage when no entry", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      const request = new NextRequest(
        new URL("/me/foo-bar/12?foo=bar", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "auth0-scope": "foo:bar"
          }
        }
      );

      const response = await authClient.handleMyAccount(request);

      const accessToken = await getAccessTokenFromSetCookieHeader(
        response,
        secret,
        `https://${DEFAULT.domain}/me/`
      );

      expect(accessToken).toBeDefined();
      expect(accessToken!.requestedScope).toEqual("foo foo:bar");
    });

    it("should update the cache when using stateless storage when entry expired", async () => {
      const cachedAccessToken = "cached_at_123";
      const session = createInitialSessionData({
        accessTokens: [
          {
            audience: `https://${DEFAULT.domain}/me/`,
            accessToken: cachedAccessToken,
            scope: "foo foo:bar",
            token_type: "Bearer",
            expiresAt: Math.floor(Date.now() / 1000) - 3600 // expired
          }
        ]
      });
      const cookie = await createSessionCookie(session, secret);

      const request = new NextRequest(
        new URL("/me/foo-bar/12?foo=bar", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "auth0-scope": "foo:bar"
          }
        }
      );

      const response = await authClient.handleMyAccount(request);

      const accessToken = await getAccessTokenFromSetCookieHeader(
        response,
        secret,
        `https://${DEFAULT.domain}/me/`
      );

      expect(accessToken).toBeDefined();
      expect(accessToken!.requestedScope).toEqual("foo foo:bar");
    });

    it("should proxy POST request to my account", async () => {
      // Override handler to echo the POST body
      server.use(
        http.post(
          `https://${DEFAULT.domain}/me/v1/foo-bar/12`,
          async ({ request }) => {
            console.log("Inside MSW handler for POST /me/v1/foo-bar/12");
            const body = await request.json();
            console.log("Received body in MSW handler:", body);
            return HttpResponse.json(body, { status: 200 });
          }
        )
      );

      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      const request = new NextRequest(
        new URL("/me/foo-bar/12", DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            cookie,
            "auth0-scope": "foo:bar"
          },
          body: JSON.stringify({ hello: "world" }),
          duplex: "half"
        }
      );

      const response = await authClient.handleMyAccount(request);

      if (response.status !== 200) {
        const errorText = await response.text();
        console.error("Error response:", errorText);
      }

      expect(response.status).toEqual(200);

      const json = await response.json();
      expect(json).toEqual({ hello: "world" });
    });

    it("should handle when oauth/token throws", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);
      const request = new NextRequest(
        new URL("/me/foo-bar/12?foo=bar", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "auth0-scope": "foo:bar"
          }
        }
      );

      // Override oauth/token handler to return an error
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          return HttpResponse.json(
            {
              error: "test_error",
              error_description: "An error from within the unit test."
            },
            { status: 401 }
          );
        })
      );

      const response = await authClient.handleMyAccount(request);
      expect(response.status).toEqual(500);

      const text = await response.text();
      expect(text).toEqual("OAuth2Error: An error from within the unit test.");
    });

    it("should handle when getTokenSet throws", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);
      const request = new NextRequest(
        new URL("/me/foo-bar/12?foo=bar", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "auth0-scope": "foo:bar"
          }
        }
      );

      authClient.getTokenSet = vi.fn().mockImplementation(() => {
        {
          throw new Error("An error from within the unit test.");
        }
      });

      const response = await authClient.handleMyAccount(request);
      expect(response.status).toEqual(500);

      const text = await response.text();
      expect(text).toEqual("An error from within the unit test.");
    });

    it("should handle when getTokenSet throws without message", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);
      const request = new NextRequest(
        new URL("/me/foo-bar/12?foo=bar", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "auth0-scope": "foo:bar"
          }
        }
      );

      authClient.getTokenSet = vi.fn().mockImplementation(() => {
        {
          throw new Error();
        }
      });

      const response = await authClient.handleMyAccount(request);
      expect(response.status).toEqual(500);

      const text = await response.text();
      expect(text).toEqual("An error occurred while proxying the request.");
    });
  });
});

const _authorizationServerMetadata = {
  issuer: `https://${DEFAULT.domain}/`,
  authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
  token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
  device_authorization_endpoint: `https://${DEFAULT.domain}/oauth/device/code`,
  userinfo_endpoint: `https://${DEFAULT.domain}/userinfo`,
  mfa_challenge_endpoint: `https://${DEFAULT.domain}/mfa/challenge`,
  jwks_uri: `https://${DEFAULT.domain}/jwks.json`,
  registration_endpoint: `https://${DEFAULT.domain}/oidc/register`,
  revocation_endpoint: `https://${DEFAULT.domain}/oauth/revoke`,
  scopes_supported: [
    "openid",
    "profile",
    "offline_access",
    "name",
    "given_name",
    "family_name",
    "nickname",
    "email",
    "email_verified",
    "picture",
    "created_at",
    "identities",
    "phone",
    "address"
  ],
  response_types_supported: [
    "code",
    "token",
    "id_token",
    "code token",
    "code id_token",
    "token id_token",
    "code token id_token"
  ],
  code_challenge_methods_supported: ["S256", "plain"],
  response_modes_supported: ["query", "fragment", "form_post"],
  subject_types_supported: ["public"],
  token_endpoint_auth_methods_supported: [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt"
  ],
  claims_supported: [
    "aud",
    "auth_time",
    "created_at",
    "email",
    "email_verified",
    "exp",
    "family_name",
    "given_name",
    "iat",
    "identities",
    "iss",
    "name",
    "nickname",
    "phone_number",
    "picture",
    "sub"
  ],
  request_uri_parameter_supported: false,
  request_parameter_supported: false,
  id_token_signing_alg_values_supported: ["HS256", "RS256", "PS256"],
  token_endpoint_auth_signing_alg_values_supported: ["RS256", "RS384", "PS256"],
  backchannel_logout_supported: true,
  backchannel_logout_session_supported: true,
  end_session_endpoint: `https://${DEFAULT.domain}/oidc/logout`,
  pushed_authorization_request_endpoint: `https://${DEFAULT.domain}/oauth/par`,
  backchannel_authentication_endpoint: `https://${DEFAULT.domain}/bc-authorize`,
  backchannel_token_delivery_modes_supported: ["poll"]
};

async function createSessionCookie(session: SessionData, secret: string) {
  const maxAge = 60 * 60; // 1 hour
  const expiration = Math.floor(Date.now() / 1000 + maxAge);
  const sessionCookie = await encrypt(session, secret, expiration);
  return `__session=${sessionCookie}`;
}

async function getAccessTokenFromSetCookieHeader(
  response: NextResponse,
  secret: string,
  audience: string
) {
  const setCookie = response.headers.get("Set-Cookie");

  const encryptedSessionCookieValue = setCookie?.split(";")[0].split("=")[1];

  const sessionCookieValue = await decrypt<SessionData>(
    encryptedSessionCookieValue!,
    secret
  );
  const accessTokens = sessionCookieValue?.payload.accessTokens;
  return accessTokens?.find((at) => at.audience === audience);
}

function createInitialSessionData(
  sessionData: Partial<SessionData> = {}
): SessionData {
  const expiresAt = Math.floor(Date.now() / 1000) + 3600;
  return {
    user: {
      sub: DEFAULT.sub,
      name: "John Doe",
      email: "john@example.com",
      picture: "https://example.com/john.jpg",
      ...sessionData.user
    },
    tokenSet: {
      accessToken: DEFAULT.accessToken,
      scope: "openid profile email",
      refreshToken: DEFAULT.refreshToken,
      expiresAt,
      ...sessionData.tokenSet
    },
    internal: {
      sid: DEFAULT.sid,
      createdAt: Math.floor(Date.now() / 1000),
      ...sessionData.internal
    },
    ...sessionData
  };
}
