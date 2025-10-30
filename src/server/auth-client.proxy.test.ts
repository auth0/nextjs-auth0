import { NextRequest, NextResponse } from "next/server.js";
import * as jose from "jose";
import * as oauth from "oauth4webapi";
import { beforeEach, describe, expect, it, Mock, vi } from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { SessionData } from "../types/index.js";
import { generateDpopKeyPair } from "../utils/dpopUtils.js";
import { AuthClient } from "./auth-client.js";
import { decrypt, encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

const DEFAULT = {
  domain: "guabu.us.auth0.com",
  clientId: "client_123",
  clientSecret: "client-secret",
  appBaseUrl: "https://example.com",
  sid: "auth0-sid",
  idToken: "idt_123",
  accessToken: "at_123",
  refreshToken: "rt_123",
  sub: "user_123",
  alg: "RS256",
  keyPair: await jose.generateKeyPair("RS256"),
  clientAssertionSigningKey: `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDbTKOQLtaZ6U1k
3fcYCMVoy8poieNPPcbj15TCLOm4Bbox73/UUxIArqczVcjtUGnL+jn5982V5EiB
y8W51m5K9mIBgEFLYdLkXk+OW5UTE/AdMPtfsIjConGrrs3mxN4WSH9kvh9Yr41r
hWUUSwqFyMOssbGE8K46Cv0WYvS7RXH9MzcyTcMSFp/60yUXH4rdHYZElF7XCdiE
63WxebxI1Qza4xkjTlbp5EWfWBQB1Ms10JO8NjrtkCXrDI57Bij5YanPAVhctcO9
z5/y9i5xEzcer8ZLO8VDiXSdEsuP/fe+UKDyYHUITD8u51p3O2JwCKvdTHduemej
3Kd1RlHrAgMBAAECggEATWdzpASkQpcSdjPSb21JIIAt5VAmJ2YKuYjyPMdVh1qe
Kdn7KJpZlFwRMBFrZjgn35Nmu1A4BFwbK5UdKUcCjvsABL+cTFsu8ORI+Fpi9+Tl
r6gGUfQhkXF85bhBfN6n9P2J2akxrz/njrf6wXrrL+V5C498tQuus1YFls0+zIpD
N+GngNOPHlGeY3gW4K/HjGuHwuJOvWNmE4KNQhBijdd50Am824Y4NV/SmsIo7z+s
8CLjp/qtihwnE4rkUHnR6M4u5lpzXOnodzkDTG8euOJds0T8DwLNTx1b+ETim35i
D/hOCVwl8QFoj2aatjuJ5LXZtZUEpGpBF2TQecB+gQKBgQDvaZ1jG/FNPnKdayYv
z5yTOhKM6JTB+WjB0GSx8rebtbFppiHGgVhOd1bLIzli9uMOPdCNuXh7CKzIgSA6
Q76Wxfuaw8F6CBIdlG9bZNL6x8wp6zF8tGz/BgW7fFKBwFYSWzTcStGr2QGtwr6F
9p1gYPSGfdERGOQc7RmhoNNHcQKBgQDqfkhpPfJlP/SdFnF7DDUvuMnaswzUsM6D
ZPhvfzdMBV8jGc0WjCW2Vd3pvsdPgWXZqAKjN7+A5HiT/8qv5ruoqOJSR9ZFZI/B
8v+8gS9Af7K56mCuCFKZmOXUmaL+3J2FKtzAyOlSLjEYyLuCgmhEA9Zo+duGR5xX
AIjx7N/ZGwKBgCZAYqQeJ8ymqJtcLkq/Sg3/3kzjMDlZxxIIYL5JwGpBemod4BGe
QuSujpCAPUABoD97QuIR+xz1Qt36O5LzlfTzBwMwOa5ssbBGMhCRKGBnIcikylBZ
Z3zLkojlES2n9FiUd/qmfZ+OWYVQsy4mO/jVJNyEJ64qou+4NjsrvfYRAoGAORki
3K1+1nSqRY3vd/zS/pnKXPx4RVoADzKI4+1gM5yjO9LOg40AqdNiw8X2lj9143fr
nH64nNQFIFSKsCZIz5q/8TUY0bDY6GsZJnd2YAg4JtkRTY8tPcVjQU9fxxtFJ+X1
9uN1HNOulNBcCD1k0hr1HH6qm5nYUb8JmY8KOr0CgYB85pvPhBqqfcWi6qaVQtK1
ukIdiJtMNPwePfsT/2KqrbnftQnAKNnhsgcYGo8NAvntX4FokOAEdunyYmm85mLp
BGKYgVXJqnm6+TJyCRac1ro3noG898P/LZ8MOBoaYQtWeWRpDc46jPrA0FqUJy+i
ca/T0LLtgmbMmxSv/MmzIg==
-----END PRIVATE KEY-----`,
  requestUri: "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
  connectAccount: {
    ticket: "5ea12747-406c-4945-abc7-232086d9a3f0",
    authSession:
      "gcPQw7YPOD0mHiSVxOSbmZmMfTckA9o3CZQyeAf1C6guAiZzXiSnU2tEws9IQNUi",
    expiresIn: 300,
    connection: "google-oauth2"
  }
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

    let mockAuthorizationServer: Mock<typeof fetch>;
    const mockFetchHandler = vi.fn();
    const mockFetch = async (
      input: RequestInfo | URL,
      init?: RequestInit
    ): Promise<Response> => {
      let url: URL;
      if (input instanceof Request) {
        url = new URL(input.url);
      } else {
        url = new URL(input);
      }

      const result = mockFetchHandler(url, init);

      if (result) {
        return result;
      }

      return mockAuthorizationServer(input, init);
    };

    let authClient: AuthClient;

    beforeEach(async () => {
      const dpopKeyPair = await generateDpopKeyPair();
      mockAuthorizationServer = getMockAuthorizationServer();
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

        fetch: mockFetch,
        useDPoP: true,
        dpopKeyPair: dpopKeyPair,
        authorizationParameters: {
          audience: "test-api",
          scope: {
            [`https://${DEFAULT.domain}/me/`]: "foo"
          }
        }
      });
    });

    beforeEach(() => {
      mockFetchHandler.mockClear();
      mockFetchHandler.mockImplementation((url: URL) => {
        if (
          url.toString() ===
          "https://guabu.us.auth0.com/me/v1/foo-bar/12?foo=bar"
        ) {
          return Response.json(myAccountResponse);
        }
      });
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

      mockFetchHandler.mockImplementation((url: URL, init: RequestInit) => {
        const token = (init.headers as any)["authorization"]
          ?.toString()
          .split(" ")[1];

        if (
          url.toString() === `https://${DEFAULT.domain}/me/v1/foo-bar/12` &&
          token === cachedAccessToken
        ) {
          return Response.json(myAccountResponse);
        }
      });

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
      // The /oauth/token endpoint was not called
      expect(mockAuthorizationServer).not.toHaveBeenCalledWith(
        `https://${DEFAULT.domain}/oauth/token`,
        expect.anything()
      );
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

      // The /oauth/token endpoint was called
      expect(mockAuthorizationServer).toHaveBeenCalledWith(
        `https://${DEFAULT.domain}/oauth/token`,
        expect.anything()
      );

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

      // The /oauth/token endpoint was called
      expect(mockAuthorizationServer).toHaveBeenCalledWith(
        `https://${DEFAULT.domain}/oauth/token`,
        expect.anything()
      );

      const accessToken = await getAccessTokenFromSetCookieHeader(
        response,
        secret,
        `https://${DEFAULT.domain}/me/`
      );

      expect(accessToken).toBeDefined();
      expect(accessToken!.requestedScope).toEqual("foo foo:bar");
    });

    it("should proxy POST request to my account", async () => {
      mockFetchHandler.mockImplementation((url: URL, init?: RequestInit) => {
        if (url.toString() === "https://guabu.us.auth0.com/me/v1/foo-bar/12") {
          return new Response(init?.body, { status: 200 });
        }
      });

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
      expect(response.status).toEqual(200);

      const json = await response.json();
      expect(json).toEqual({ hello: "world" });
    });
  });
});

const _authorizationServerMetadata = {
  issuer: "https://guabu.us.auth0.com/",
  authorization_endpoint: "https://guabu.us.auth0.com/authorize",
  token_endpoint: "https://guabu.us.auth0.com/oauth/token",
  device_authorization_endpoint: "https://guabu.us.auth0.com/oauth/device/code",
  userinfo_endpoint: "https://guabu.us.auth0.com/userinfo",
  mfa_challenge_endpoint: "https://guabu.us.auth0.com/mfa/challenge",
  jwks_uri: "https://guabu.us.auth0.com/.well-known/jwks.json",
  registration_endpoint: "https://guabu.us.auth0.com/oidc/register",
  revocation_endpoint: "https://guabu.us.auth0.com/oauth/revoke",
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
  end_session_endpoint: "https://guabu.us.auth0.com/oidc/logout",
  pushed_authorization_request_endpoint: "https://guabu.us.auth0.com/oauth/par",
  backchannel_authentication_endpoint:
    "https://guabu.us.auth0.com/bc-authorize",
  backchannel_token_delivery_modes_supported: ["poll"]
};

function getMockAuthorizationServer({
  tokenEndpointResponse,
  tokenEndpointErrorResponse,
  tokenEndpointFetchError,
  discoveryResponse,
  audience,
  nonce,
  keyPair = DEFAULT.keyPair,
  onParRequest,
  onBackchannelAuthRequest,
  onConnectAccountRequest,
  onCompleteConnectAccountRequest,
  completeConnectAccountErrorResponse
}: {
  tokenEndpointResponse?: oauth.TokenEndpointResponse | oauth.OAuth2Error;
  tokenEndpointErrorResponse?: oauth.OAuth2Error;
  tokenEndpointFetchError?: Error;
  discoveryResponse?: Response;
  audience?: string;
  nonce?: string;
  keyPair?: jose.GenerateKeyPairResult;
  onParRequest?: (request: Request) => Promise<void>;
  onBackchannelAuthRequest?: (request: Request) => Promise<void>;
  onConnectAccountRequest?: (request: Request) => Promise<void>;
  onCompleteConnectAccountRequest?: (request: Request) => Promise<void>;
  completeConnectAccountErrorResponse?: Response;
} = {}) {
  // this function acts as a mock authorization server
  return vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      let url: URL;
      if (input instanceof Request) {
        url = new URL(input.url);
      } else {
        url = new URL(input);
      }

      if (url.pathname === "/oauth/token") {
        if (tokenEndpointFetchError) {
          throw tokenEndpointFetchError;
        }

        const jwt = await new jose.SignJWT({
          sid: DEFAULT.sid,
          auth_time: Date.now(),
          nonce: nonce ?? "nonce-value",
          "https://example.com/custom_claim": "value"
        })
          .setProtectedHeader({ alg: DEFAULT.alg })
          .setSubject(DEFAULT.sub)
          .setIssuedAt()
          .setIssuer(_authorizationServerMetadata.issuer)
          .setAudience(audience ?? DEFAULT.clientId)
          .setExpirationTime("2h")
          .sign(keyPair.privateKey);

        if (tokenEndpointErrorResponse) {
          return Response.json(tokenEndpointErrorResponse, {
            status: 400
          });
        }
        return Response.json(
          tokenEndpointResponse ?? {
            token_type: "Bearer",
            access_token: DEFAULT.accessToken,
            refresh_token: DEFAULT.refreshToken,
            id_token: jwt,
            expires_in: 86400 // expires in 10 days
          }
        );
      }
      // discovery URL
      if (url.pathname === "/.well-known/openid-configuration") {
        return discoveryResponse ?? Response.json(_authorizationServerMetadata);
      }
      // PAR endpoint
      if (url.pathname === "/oauth/par") {
        if (onParRequest) {
          await onParRequest(new Request(input, init));
        }

        return Response.json(
          { request_uri: DEFAULT.requestUri, expires_in: 30 },
          {
            status: 201
          }
        );
      }
      // Backchannel Authorize endpoint
      if (url.pathname === "/bc-authorize") {
        if (onBackchannelAuthRequest) {
          await onBackchannelAuthRequest(new Request(input, init));
        }

        return Response.json(
          {
            auth_req_id: "auth-req-id",
            expires_in: 30,
            interval: 0.01
          },
          {
            status: 200
          }
        );
      }
      // Connect Account
      if (url.pathname === "/me/v1/connected-accounts/connect") {
        if (onConnectAccountRequest) {
          // Connect Account uses a fetcher for DPoP.
          // This means it creates a `new Request()` internally.
          // When a body is sent as an object (`{ foo: 'bar' }`), it will be exposed as a `ReadableStream` below.
          // When a `ReadableStream` is used as body for a `new Request()`, setting `duplex: 'half'` is required.
          // https://github.com/whatwg/fetch/pull/1457
          await onConnectAccountRequest(
            new Request(input, { ...init, duplex: "half" } as RequestInit)
          );
        }

        return Response.json(
          {
            connect_uri: `https://${DEFAULT.domain}/connect`,
            auth_session: DEFAULT.connectAccount.authSession,
            connect_params: {
              ticket: DEFAULT.connectAccount.ticket
            },
            expires_in: 300
          },
          {
            status: 201
          }
        );
      }
      // Connect Account complete
      if (url.pathname === "/me/v1/connected-accounts/complete") {
        if (onCompleteConnectAccountRequest) {
          // Complete Connect Account uses a fetcher for DPoP.
          // This means it creates a `new Request()` internally.
          // When a body is sent as an object (`{ foo: 'bar' }`), it will be exposed as a `ReadableStream` below.
          // When a `ReadableStream` is used as body for a `new Request()`, setting `duplex: 'half'` is required.
          // https://github.com/whatwg/fetch/pull/1457
          await onCompleteConnectAccountRequest(
            new Request(input, { ...init, duplex: "half" } as RequestInit)
          );
        }

        if (completeConnectAccountErrorResponse) {
          return completeConnectAccountErrorResponse;
        }

        return Response.json(
          {
            id: "cac_abc123",
            connection: DEFAULT.connectAccount.connection,
            access_type: "offline",
            scopes: ["openid", "profile", "email"],
            created_at: new Date().toISOString(),
            expires_at: new Date(
              Date.now() + 1000 * 60 * 60 * 24 * 30
            ).toISOString() // 30 days
          },
          {
            status: 201
          }
        );
      }

      return new Response(null, { status: 404 });
    }
  );
}

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
