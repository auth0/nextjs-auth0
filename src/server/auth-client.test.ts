import { NextRequest, NextResponse } from "next/server.js";
import * as jose from "jose";
import * as oauth from "oauth4webapi";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import {
  AccessTokenError,
  AccessTokenErrorCode,
  BackchannelAuthenticationError,
  ConnectAccountError,
  ConnectAccountErrorCodes,
  InvalidConfigurationError,
  MyAccountApiError
} from "../errors/index.js";
import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import {
  AccessTokenSet,
  RESPONSE_TYPES,
  SessionData,
  SUBJECT_TOKEN_TYPES
} from "../types/index.js";
import { DEFAULT_SCOPES } from "../utils/constants.js";
import { AuthClient } from "./auth-client.js";
import { decrypt, encrypt } from "./cookies.js";
import { StatefulSessionStore } from "./session/stateful-session-store.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionState, TransactionStore } from "./transaction-store.js";

function createSessionData(sessionData: Partial<SessionData>): SessionData {
  return {
    tokenSet: { accessToken: "<my_access_token>", expiresAt: 123456 },
    user: {
      sub: "<my_sub>"
    },
    internal: {
      sid: "<my_sid>",
      createdAt: 123456
    },
    ...sessionData
  };
}

describe("Authentication Client", async () => {
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
      async (
        input: RequestInfo | URL,
        init?: RequestInit
      ): Promise<Response> => {
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
          return (
            discoveryResponse ?? Response.json(_authorizationServerMetadata)
          );
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

  async function generateLogoutToken({
    claims = {},
    audience = DEFAULT.clientId,
    issuer = _authorizationServerMetadata.issuer,
    alg = DEFAULT.alg,

    privateKey = DEFAULT.keyPair.privateKey
  }: {
    claims?: any;
    audience?: string;
    issuer?: string;
    alg?: string;
    privateKey?: jose.CryptoKey;
  }): Promise<string> {
    return await new jose.SignJWT({
      events: {
        "http://schemas.openid.net/event/backchannel-logout": {}
      },
      sub: DEFAULT.sub,
      sid: DEFAULT.sid,
      ...claims
    })
      .setProtectedHeader({ alg, typ: "logout+jwt" })
      .setIssuedAt()
      .setIssuer(issuer)
      .setAudience(audience)
      .setExpirationTime("2h")
      .setJti("some-jti")
      .sign(privateKey);
  }

  async function getCachedJWKS(): Promise<jose.ExportedJWKSCache> {
    const publicJwk = await jose.exportJWK(DEFAULT.keyPair.publicKey);

    return {
      jwks: {
        keys: [publicJwk]
      },
      uat: Date.now() - 1000 * 60
    };
  }

  describe("initialization", async () => {
    it("should throw an error if the openid scope is not included", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });

      expect(
        () =>
          new AuthClient({
            transactionStore,
            sessionStore,

            domain: DEFAULT.domain,
            clientId: DEFAULT.clientId,
            clientSecret: DEFAULT.clientSecret,

            secret,
            appBaseUrl: DEFAULT.appBaseUrl,

            routes: getDefaultRoutes(),

            authorizationParameters: {
              scope: "profile email"
            },

            fetch: getMockAuthorizationServer()
          })
      ).toThrowError();
    });

    it("should throw an error if the openid scope is not included when using a map", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });

      expect(
        () =>
          new AuthClient({
            transactionStore,
            sessionStore,

            domain: DEFAULT.domain,
            clientId: DEFAULT.clientId,
            clientSecret: DEFAULT.clientSecret,

            secret,
            appBaseUrl: DEFAULT.appBaseUrl,

            routes: getDefaultRoutes(),

            authorizationParameters: {
              audience: "test-1",
              scope: {
                "test-1": "profile email"
              }
            },

            fetch: getMockAuthorizationServer()
          })
      ).toThrowError();
    });

    it("should not throw an error if the scope is not provided for the default audience when using a map", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });

      expect(
        () =>
          new AuthClient({
            transactionStore,
            sessionStore,

            domain: DEFAULT.domain,
            clientId: DEFAULT.clientId,
            clientSecret: DEFAULT.clientSecret,

            secret,
            appBaseUrl: DEFAULT.appBaseUrl,

            routes: getDefaultRoutes(),

            authorizationParameters: {
              audience: "test-1",
              scope: {
                "test-2": "profile email"
              }
            },

            fetch: getMockAuthorizationServer()
          })
      ).not.toThrowError();
    });

    it("should warn when allowInsecureRequests is enabled in production", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      vi.stubEnv("NODE_ENV", "production");

      try {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });

        new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          allowInsecureRequests: true,
          fetch: getMockAuthorizationServer()
        });

        expect(warnSpy).toHaveBeenCalledWith(
          "allowInsecureRequests is enabled in a production environment. This is not recommended."
        );
      } finally {
        warnSpy.mockRestore();
        vi.unstubAllEnvs();
      }
    });
  });

  describe("handler", async () => {
    it("should call the login handler if the path is /auth/login", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest("https://example.com/auth/login", {
        method: "GET"
      });
      authClient.handleLogin = vi.fn();
      await authClient.handler(request);
      expect(authClient.handleLogin).toHaveBeenCalled();
    });

    it("should call the callback handler if the path is /auth/callback", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest("https://example.com/auth/callback", {
        method: "GET"
      });
      authClient.handleCallback = vi.fn();
      await authClient.handler(request);
      expect(authClient.handleCallback).toHaveBeenCalled();
    });

    it("should call the logout handler if the path is /auth/logout", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest("https://example.com/auth/logout", {
        method: "GET"
      });
      authClient.handleLogout = vi.fn();
      await authClient.handler(request);
      expect(authClient.handleLogout).toHaveBeenCalled();
    });

    it("should call the profile handler if the path is /auth/profile", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest("https://example.com/auth/profile", {
        method: "GET"
      });
      authClient.handleProfile = vi.fn();
      await authClient.handler(request);
      expect(authClient.handleProfile).toHaveBeenCalled();
    });

    it("should call the handleAccessToken method if the path is /auth/access-token and enableAccessTokenEndpoint is true", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        enableAccessTokenEndpoint: true,

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest("https://example.com/auth/access-token", {
        method: "GET"
      });
      authClient.handleAccessToken = vi.fn();
      await authClient.handler(request);
      expect(authClient.handleAccessToken).toHaveBeenCalled();
    });

    it("should not call the handleAccessToken method if the path is /auth/access-token but enableAccessTokenEndpoint is false", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        enableAccessTokenEndpoint: false,

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest("https://example.com/auth/access-token", {
        method: "GET"
      });
      authClient.handleAccessToken = vi.fn();
      const response = await authClient.handler(request);
      expect(authClient.handleAccessToken).not.toHaveBeenCalled();
      // When a route doesn't match, the handler returns a NextResponse.next() with status 200
      expect(response.status).toBe(200);
    });

    it("should use the default value (true) for enableAccessTokenEndpoint when not explicitly provided", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        // enableAccessTokenEndpoint not specified, should default to true

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest("https://example.com/auth/access-token", {
        method: "GET"
      });
      authClient.handleAccessToken = vi.fn();
      await authClient.handler(request);
      expect(authClient.handleAccessToken).toHaveBeenCalled();
    });

    it("should call the back-channel logout handler if the path is /auth/backchannel-logout", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest(
        "https://example.com/auth/backchannel-logout",
        {
          method: "POST"
        }
      );
      authClient.handleBackChannelLogout = vi.fn();
      await authClient.handler(request);
      expect(authClient.handleBackChannelLogout).toHaveBeenCalled();
    });

    describe("rolling sessions - no matching auth route", async () => {
      it("should update the session expiry if a session exists", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret,

          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        const session: SessionData = {
          user: { sub: DEFAULT.sub },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: 123456
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const sessionCookie = await encrypt(session, secret, expiration);
        const headers = new Headers();
        headers.append("cookie", `__session=${sessionCookie}`);
        const request = new NextRequest(
          "https://example.com/dashboard/projects",
          {
            method: "GET",
            headers
          }
        );

        const response = await authClient.handler(request);

        // assert session has been updated
        const updatedSessionCookie = response.cookies.get("__session");
        expect(updatedSessionCookie).toBeDefined();
        const { payload: updatedSessionCookieValue } = (await decrypt(
          updatedSessionCookie!.value,
          secret
        )) as jose.JWTDecryptResult;
        expect(updatedSessionCookieValue).toEqual(
          expect.objectContaining({
            user: {
              sub: DEFAULT.sub
            },
            tokenSet: {
              accessToken: "at_123",
              refreshToken: "rt_123",
              expiresAt: expect.any(Number)
            },
            internal: {
              sid: DEFAULT.sid,
              createdAt: expect.any(Number)
            }
          })
        );

        // assert that the session expiry has been extended by the inactivity duration
        expect(updatedSessionCookie?.maxAge).toEqual(1800);
      });

      it("should pass the request through if there is no session", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret,

          rolling: true,
          absoluteDuration: 3600,
          inactivityDuration: 1800
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        const request = new NextRequest(
          "https://example.com/dashboard/projects",
          {
            method: "GET"
          }
        );

        authClient.getTokenSet = vi.fn();

        const response = await authClient.handler(request);
        expect(authClient.getTokenSet).not.toHaveBeenCalled();

        // assert session has not been updated
        const updatedSessionCookie = response.cookies.get("__session");
        expect(updatedSessionCookie).toBeUndefined();
      });
    });

    describe("with custom routes", async () => {
      it("should call the login handler when the configured route is called", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          routes: {
            ...getDefaultRoutes(),
            login: "/custom-login"
          }
        });
        const request = new NextRequest(
          new URL("/custom-login", DEFAULT.appBaseUrl),
          {
            method: "GET"
          }
        );

        authClient.handleLogin = vi.fn();
        await authClient.handler(request);
        expect(authClient.handleLogin).toHaveBeenCalled();
      });

      it("should call the logout handler when the configured route is called", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          routes: {
            ...getDefaultRoutes(),
            logout: "/custom-logout"
          }
        });
        const request = new NextRequest(
          new URL("/custom-logout", DEFAULT.appBaseUrl),
          {
            method: "GET"
          }
        );

        authClient.handleLogout = vi.fn();
        await authClient.handler(request);
        expect(authClient.handleLogout).toHaveBeenCalled();
      });

      it("should call the callback handler when the configured route is called", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          routes: {
            ...getDefaultRoutes(),
            callback: "/custom-callback"
          }
        });
        const request = new NextRequest(
          new URL("/custom-callback", DEFAULT.appBaseUrl),
          {
            method: "GET"
          }
        );

        authClient.handleCallback = vi.fn();
        await authClient.handler(request);
        expect(authClient.handleCallback).toHaveBeenCalled();
      });

      it("should call the backChannelLogout handler when the configured route is called", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          routes: {
            ...getDefaultRoutes(),
            backChannelLogout: "/custom-backchannel-logout"
          }
        });
        const request = new NextRequest(
          new URL("/custom-backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST"
          }
        );

        authClient.handleBackChannelLogout = vi.fn();
        await authClient.handler(request);
        expect(authClient.handleBackChannelLogout).toHaveBeenCalled();
      });

      it("should call the profile handler when the configured route is called", async () => {
        process.env.NEXT_PUBLIC_PROFILE_ROUTE = "/custom-profile";

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });
        const request = new NextRequest(
          new URL("/custom-profile", DEFAULT.appBaseUrl),
          {
            method: "GET"
          }
        );

        authClient.handleProfile = vi.fn();
        await authClient.handler(request);
        expect(authClient.handleProfile).toHaveBeenCalled();

        delete process.env.NEXT_PUBLIC_PROFILE_ROUTE;
      });

      it("should call the access-token handler when the configured route is called", async () => {
        process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE = "/custom-access-token";

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });
        const request = new NextRequest(
          new URL("/custom-access-token", DEFAULT.appBaseUrl),
          {
            method: "GET"
          }
        );

        authClient.handleAccessToken = vi.fn();
        await authClient.handler(request);
        expect(authClient.handleAccessToken).toHaveBeenCalled();

        delete process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE;
      });
    });

    describe("with a base path", async () => {
      beforeAll(() => {
        process.env.NEXT_PUBLIC_BASE_PATH = "/base-path";
      });

      afterAll(() => {
        delete process.env.NEXT_PUBLIC_BASE_PATH;
      });

      it("should call the appropriate handlers when routes are called with base path", async () => {
        const testCases = [
          {
            path: "/auth/login",
            method: "GET",
            handler: "handleLogin"
          },
          {
            path: "/auth/logout",
            method: "GET",
            handler: "handleLogout"
          },
          {
            path: "/auth/callback",
            method: "GET",
            handler: "handleCallback"
          },
          {
            path: "/auth/backchannel-logout",
            method: "POST",
            handler: "handleBackChannelLogout"
          },
          {
            path: "/auth/profile",
            method: "GET",
            handler: "handleProfile"
          },
          {
            path: "/auth/access-token",
            method: "GET",
            handler: "handleAccessToken"
          }
        ];

        for (const testCase of testCases) {
          const secret = await generateSecret(32);
          const transactionStore = new TransactionStore({
            secret
          });
          const sessionStore = new StatelessSessionStore({
            secret
          });
          const authClient = new AuthClient({
            transactionStore,
            sessionStore,

            domain: DEFAULT.domain,
            clientId: DEFAULT.clientId,
            clientSecret: DEFAULT.clientSecret,

            secret,
            appBaseUrl: DEFAULT.appBaseUrl,

            routes: getDefaultRoutes(),

            fetch: getMockAuthorizationServer()
          });

          const request = new NextRequest(
            // Simulate real Next.js behavior: basePath is included in pathname.
            // With basePath='/base-path', Next.js sends pathname='/base-path/auth/login'
            // to middleware. The handler must strip the basePath to match routes.
            new URL(
              `${process.env.NEXT_PUBLIC_BASE_PATH}${testCase.path}`,
              DEFAULT.appBaseUrl
            ),
            {
              method: testCase.method
            }
          );

          // Mock the basePath property that Next.js provides in middleware
          Object.defineProperty(request.nextUrl, "basePath", {
            value: process.env.NEXT_PUBLIC_BASE_PATH,
            writable: false
          });

          (authClient as any)[testCase.handler] = vi.fn();
          await authClient.handler(request);
          expect((authClient as any)[testCase.handler]).toHaveBeenCalled();
        }
      });

      it("should handle requests without basePath (backward compatibility)", async () => {
        // Clear basePath to test backward compatibility
        delete process.env.NEXT_PUBLIC_BASE_PATH;

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({ secret });
        const sessionStore = new StatelessSessionStore({ secret });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          routes: getDefaultRoutes(),
          fetch: getMockAuthorizationServer()
        });

        const request = new NextRequest(
          new URL("/auth/login", DEFAULT.appBaseUrl),
          { method: "GET" }
        );

        authClient.handleLogin = vi.fn();
        await authClient.handler(request);
        expect(authClient.handleLogin).toHaveBeenCalled();

        // Restore basePath for subsequent tests
        process.env.NEXT_PUBLIC_BASE_PATH = "/base-path";
      });

      it("should handle hardcoded /me routes with basePath", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({ secret });
        const sessionStore = new StatelessSessionStore({ secret });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          routes: getDefaultRoutes(),
          fetch: getMockAuthorizationServer()
        });

        const request = new NextRequest(
          new URL(
            `${process.env.NEXT_PUBLIC_BASE_PATH}/me/profile`,
            DEFAULT.appBaseUrl
          ),
          { method: "GET" }
        );

        // Mock the basePath property that Next.js provides in middleware
        Object.defineProperty(request.nextUrl, "basePath", {
          value: process.env.NEXT_PUBLIC_BASE_PATH,
          writable: false
        });

        authClient.handleMyAccount = vi.fn();
        await authClient.handler(request);
        expect(authClient.handleMyAccount).toHaveBeenCalled();
      });

      it("should handle hardcoded /my-org routes with basePath", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({ secret });
        const sessionStore = new StatelessSessionStore({ secret });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          routes: getDefaultRoutes(),
          fetch: getMockAuthorizationServer()
        });

        const request = new NextRequest(
          new URL(
            `${process.env.NEXT_PUBLIC_BASE_PATH}/my-org/members`,
            DEFAULT.appBaseUrl
          ),
          { method: "GET" }
        );

        // Mock the basePath property that Next.js provides in middleware
        Object.defineProperty(request.nextUrl, "basePath", {
          value: process.env.NEXT_PUBLIC_BASE_PATH,
          writable: false
        });

        authClient.handleMyOrg = vi.fn();
        await authClient.handler(request);
        expect(authClient.handleMyOrg).toHaveBeenCalled();
      });
    });
  });

  describe("handleLogin", async () => {
    it("should redirect to the authorization server and store the transaction state", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest(
        new URL("/auth/login", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleLogin(request);
      expect(response.status).toEqual(307);
      expect(response.headers.get("Location")).not.toBeNull();

      const authorizationUrl = new URL(response.headers.get("Location")!);
      expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

      // query parameters
      expect(authorizationUrl.searchParams.get("client_id")).toEqual(
        DEFAULT.clientId
      );
      expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
        `${DEFAULT.appBaseUrl}/auth/callback`
      );
      expect(authorizationUrl.searchParams.get("response_type")).toEqual(
        "code"
      );
      expect(
        authorizationUrl.searchParams.get("code_challenge")
      ).not.toBeNull();
      expect(
        authorizationUrl.searchParams.get("code_challenge_method")
      ).toEqual("S256");
      expect(authorizationUrl.searchParams.get("state")).not.toBeNull();
      expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull();
      expect(authorizationUrl.searchParams.get("scope")).toEqual(
        "openid profile email offline_access"
      );

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      );
      expect(transactionCookie).toBeDefined();
      expect(
        (
          (await decrypt(
            transactionCookie!.value,
            secret
          )) as jose.JWTDecryptResult
        ).payload
      ).toEqual(
        expect.objectContaining({
          nonce: authorizationUrl.searchParams.get("nonce"),
          codeVerifier: expect.any(String),
          responseType: RESPONSE_TYPES.CODE,
          state: authorizationUrl.searchParams.get("state"),
          returnTo: "/"
        })
      );
    });

    it("should configure redirect_uri when appBaseUrl isnt the root", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: `${DEFAULT.appBaseUrl}/sub-path`,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const request = new NextRequest(
        new URL("/auth/login", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleLogin(request);
      const authorizationUrl = new URL(response.headers.get("Location")!);

      expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
        `${DEFAULT.appBaseUrl}/sub-path/auth/callback`
      );
    });

    describe("with a base path", async () => {
      beforeAll(() => {
        process.env.NEXT_PUBLIC_BASE_PATH = "/base-path";
      });

      afterAll(() => {
        delete process.env.NEXT_PUBLIC_BASE_PATH;
      });

      it("should prepend the base path to the redirect_uri", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: `${DEFAULT.appBaseUrl}`,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });
        const request = new NextRequest(
          new URL(
            process.env.NEXT_PUBLIC_BASE_PATH + "/auth/login",
            DEFAULT.appBaseUrl
          ),
          {
            method: "GET"
          }
        );

        const response = await authClient.handleLogin(request);
        const authorizationUrl = new URL(response.headers.get("Location")!);

        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/base-path/auth/callback`
        );
      });
    });

    it("should infer appBaseUrl from request host when not configured", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const request = new NextRequest(
        new URL("/auth/login", "https://preview.example.com"),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleLogin(request);
      const authorizationUrl = new URL(response.headers.get("Location")!);

      expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
        "https://preview.example.com/auth/callback"
      );
    });

    it("should prefer forwarded headers when inferring appBaseUrl", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const request = new NextRequest(
        new URL("/auth/login", "http://internal.example"),
        {
          method: "GET",
          headers: {
            "x-forwarded-host": "preview.example.com",
            "x-forwarded-proto": "https"
          }
        }
      );

      const response = await authClient.handleLogin(request);
      const authorizationUrl = new URL(response.headers.get("Location")!);

      expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
        "https://preview.example.com/auth/callback"
      );
    });

    it("should throw when appBaseUrl cannot be inferred from the request", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const request = {
        headers: new Headers()
      } as unknown as NextRequest;

      await expect(
        authClient.startInteractiveLogin({}, request)
      ).rejects.toThrow(InvalidConfigurationError);
    });

    it("should return an error if the discovery endpoint could not be fetched", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          discoveryResponse: new Response(null, { status: 500 })
        })
      });

      const request = new NextRequest(
        new URL("/auth/login", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleLogin(request);
      expect(response.status).toEqual(500);
      expect(await response.text()).toContain(
        "An error occurred while trying to initiate the login request."
      );
    });

    describe("authorization parameters", async () => {
      it("should forward the query parameters to the authorization server", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
        loginUrl.searchParams.set("custom_param", "custom_value");
        loginUrl.searchParams.set("audience", "urn:mystore:api");
        const request = new NextRequest(loginUrl, {
          method: "GET"
        });

        const response = await authClient.handleLogin(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        );
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        );
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        );
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull();
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256");
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull();
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull();
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access"
        );
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "custom_value"
        );
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "urn:mystore:api"
        );

        // transaction state
        const transactionCookie = response.cookies.get(
          `__txn_${authorizationUrl.searchParams.get("state")}`
        );
        expect(transactionCookie).toBeDefined();
        expect(
          (
            (await decrypt(
              transactionCookie!.value,
              secret
            )) as jose.JWTDecryptResult
          ).payload
        ).toEqual(
          expect.objectContaining({
            nonce: authorizationUrl.searchParams.get("nonce"),
            codeVerifier: expect.any(String),
            responseType: RESPONSE_TYPES.CODE,
            state: authorizationUrl.searchParams.get("state"),
            returnTo: "/"
          })
        );
      });

      it("should forward the configured authorization parameters to the authorization server", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          authorizationParameters: {
            scope: "openid profile email offline_access custom_scope",
            audience: "urn:mystore:api",
            custom_param: "custom_value"
          },

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
        const request = new NextRequest(loginUrl, {
          method: "GET"
        });

        const response = await authClient.handleLogin(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        );
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        );
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        );
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull();
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256");
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull();
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull();
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access custom_scope"
        );
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "custom_value"
        );
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "urn:mystore:api"
        );
      });

      it("should override the configured authorization parameters with the query parameters", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          authorizationParameters: {
            audience: "from-config",
            custom_param: "from-config"
          },

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
        loginUrl.searchParams.set("custom_param", "from-query");
        loginUrl.searchParams.set("audience", "from-query");
        const request = new NextRequest(loginUrl, {
          method: "GET"
        });

        const response = await authClient.handleLogin(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        );
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        );
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        );
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull();
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256");
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull();
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull();
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access"
        );
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "from-query"
        );
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "from-query"
        );
      });

      it("should protect internal params while ignoring redirect_uri overrides", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          authorizationParameters: {
            client_id: "from-config",
            redirect_uri: "https://config.example.com/auth/callback",
            response_type: "from-config",
            code_challenge: "from-config",
            code_challenge_method: "from-config",
            state: "from-config",
            nonce: "from-config",
            // allowed to be overridden
            custom_param: "from-config",
            scope: "openid profile email offline_access custom_scope",
            audience: "from-config"
          },

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
        loginUrl.searchParams.set("client_id", "from-query");
        loginUrl.searchParams.set(
          "redirect_uri",
          "https://query.example.com/auth/callback"
        );
        loginUrl.searchParams.set("response_type", "from-query");
        loginUrl.searchParams.set("code_challenge", "from-query");
        loginUrl.searchParams.set("code_challenge_method", "from-query");
        loginUrl.searchParams.set("state", "from-query");
        loginUrl.searchParams.set("nonce", "from-query");
        // allowed to be overridden
        loginUrl.searchParams.set("custom_param", "from-query");
        const request = new NextRequest(loginUrl, {
          method: "GET"
        });

        const response = await authClient.handleLogin(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        );
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        );
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        );
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull();
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256");
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull();
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull();
        // allowed to be overridden
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access custom_scope"
        );
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "from-query"
        );
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "from-config"
        );
      });

      it("should not forward parameters with null or undefined values", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          authorizationParameters: {
            scope: "openid profile email offline_access custom_scope",
            audience: null,
            custom_param: undefined
          },

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });
        const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
        const request = new NextRequest(loginUrl, {
          method: "GET"
        });

        const response = await authClient.handleLogin(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        );
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        );
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        );
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull();
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256");
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull();
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull();
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access custom_scope"
        );
        expect(authorizationUrl.searchParams.get("custom_param")).toBeNull();
        expect(authorizationUrl.searchParams.get("audience")).toBeNull();
      });
    });

    it("should store the maxAge in the transaction state and forward it to the authorization server", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        authorizationParameters: {
          max_age: 3600
        },

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
      const request = new NextRequest(loginUrl, {
        method: "GET"
      });

      const response = await authClient.handleLogin(request);
      const authorizationUrl = new URL(response.headers.get("Location")!);

      expect(authorizationUrl.searchParams.get("max_age")).toEqual("3600");

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      );
      expect(transactionCookie).toBeDefined();
      expect(
        (
          (await decrypt(
            transactionCookie!.value,
            secret
          )) as jose.JWTDecryptResult
        ).payload
      ).toEqual(
        expect.objectContaining({
          nonce: authorizationUrl.searchParams.get("nonce"),
          maxAge: 3600,
          codeVerifier: expect.any(String),
          responseType: RESPONSE_TYPES.CODE,
          state: authorizationUrl.searchParams.get("state"),
          returnTo: "/"
        })
      );
    });

    it("should store the returnTo path in the transaction state", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
      loginUrl.searchParams.set("returnTo", "/dashboard");
      const request = new NextRequest(loginUrl, {
        method: "GET"
      });

      const response = await authClient.handleLogin(request);
      const authorizationUrl = new URL(response.headers.get("Location")!);

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      );
      expect(transactionCookie).toBeDefined();
      expect(
        (
          (await decrypt(
            transactionCookie!.value,
            secret
          )) as jose.JWTDecryptResult
        ).payload
      ).toEqual(
        expect.objectContaining({
          nonce: authorizationUrl.searchParams.get("nonce"),
          codeVerifier: expect.any(String),
          responseType: RESPONSE_TYPES.CODE,
          state: authorizationUrl.searchParams.get("state"),
          returnTo: "/dashboard"
        })
      );
    });

    it("should prevent open redirects originating from the returnTo parameter", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });
      const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
      loginUrl.searchParams.set("returnTo", "https://google.com");
      const request = new NextRequest(loginUrl, {
        method: "GET"
      });

      const response = await authClient.handleLogin(request);
      const authorizationUrl = new URL(response.headers.get("Location")!);

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      );
      expect(transactionCookie).toBeDefined();
      expect(
        (
          (await decrypt(
            transactionCookie!.value,
            secret
          )) as jose.JWTDecryptResult
        ).payload
      ).toEqual(
        expect.objectContaining({
          nonce: authorizationUrl.searchParams.get("nonce"),
          codeVerifier: expect.any(String),
          responseType: RESPONSE_TYPES.CODE,
          state: authorizationUrl.searchParams.get("state"),
          returnTo: "/"
        })
      );
    });

    describe("with pushed authorization requests", async () => {
      it("should return an error if the authorization server does not support PAR", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          pushedAuthorizationRequests: true,
          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),
          fetch: getMockAuthorizationServer({
            discoveryResponse: Response.json(
              {
                ..._authorizationServerMetadata,
                pushed_authorization_request_endpoint: null
              },
              {
                status: 200,
                headers: {
                  "content-type": "application/json"
                }
              }
            )
          })
        });

        const request = new NextRequest(
          new URL("/auth/login", DEFAULT.appBaseUrl),
          {
            method: "GET"
          }
        );
        const response = await authClient.handleLogin(request);

        expect(response.status).toEqual(500);
        expect(await response.text()).toEqual(
          "An error occurred while trying to initiate the login request."
        );
      });

      it("should redirect to the authorization server with the request_uri and store the transaction state", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          pushedAuthorizationRequests: true,
          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),
          fetch: getMockAuthorizationServer({
            onParRequest: async (request) => {
              const params = new URLSearchParams(await request.text());
              expect(params.get("client_id")).toEqual(DEFAULT.clientId);
              expect(params.get("redirect_uri")).toEqual(
                `${DEFAULT.appBaseUrl}/auth/callback`
              );
              expect(params.get("response_type")).toEqual("code");
              expect(params.get("code_challenge")).toEqual(expect.any(String));
              expect(params.get("code_challenge_method")).toEqual("S256");
              expect(params.get("state")).toEqual(expect.any(String));
              expect(params.get("nonce")).toEqual(expect.any(String));
              expect(params.get("scope")).toEqual(
                "openid profile email offline_access"
              );
            }
          })
        });

        const request = new NextRequest(
          new URL("/auth/login", DEFAULT.appBaseUrl),
          {
            method: "GET"
          }
        );

        const response = await authClient.handleLogin(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);
        // query parameters should only include the `request_uri` and not the standard auth params
        expect(authorizationUrl.searchParams.get("request_uri")).toEqual(
          DEFAULT.requestUri
        );
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        );
        expect(authorizationUrl.searchParams.get("redirect_uri")).toBeNull();
        expect(authorizationUrl.searchParams.get("response_type")).toBeNull();
        expect(authorizationUrl.searchParams.get("code_challenge")).toBeNull();
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toBeNull();
        expect(authorizationUrl.searchParams.get("state")).toBeNull();
        expect(authorizationUrl.searchParams.get("nonce")).toBeNull();
        expect(authorizationUrl.searchParams.get("scope")).toBeNull();

        // transaction state
        const transactionCookies = response.cookies
          .getAll()
          .filter((c) => c.name.startsWith("__txn_"));
        expect(transactionCookies.length).toEqual(1);
        const transactionCookie = transactionCookies[0];
        const state = transactionCookie.name.replace("__txn_", "");
        expect(transactionCookie).toBeDefined();
        expect(
          (
            (await decrypt(
              transactionCookie.value,
              secret
            )) as jose.JWTDecryptResult
          ).payload
        ).toEqual(
          expect.objectContaining({
            nonce: expect.any(String),
            codeVerifier: expect.any(String),
            responseType: RESPONSE_TYPES.CODE,
            state,
            returnTo: "/"
          })
        );
      });

      describe("with a base path", async () => {
        beforeAll(() => {
          process.env.NEXT_PUBLIC_BASE_PATH = "/base-path";
        });

        afterAll(() => {
          delete process.env.NEXT_PUBLIC_BASE_PATH;
        });

        it("should prepend the base path to the redirect_uri", async () => {
          const secret = await generateSecret(32);
          const transactionStore = new TransactionStore({
            secret
          });
          const sessionStore = new StatelessSessionStore({
            secret
          });
          const authClient = new AuthClient({
            transactionStore,
            sessionStore,
            domain: DEFAULT.domain,
            clientId: DEFAULT.clientId,
            clientSecret: DEFAULT.clientSecret,
            pushedAuthorizationRequests: true,
            secret,
            appBaseUrl: DEFAULT.appBaseUrl,

            routes: getDefaultRoutes(),
            fetch: getMockAuthorizationServer({
              onParRequest: async (request) => {
                const params = new URLSearchParams(await request.text());
                expect(params.get("client_id")).toEqual(DEFAULT.clientId);
                expect(params.get("redirect_uri")).toEqual(
                  `${DEFAULT.appBaseUrl}/base-path/auth/callback`
                );
                expect(params.get("response_type")).toEqual("code");
                expect(params.get("code_challenge")).toEqual(
                  expect.any(String)
                );
                expect(params.get("code_challenge_method")).toEqual("S256");
                expect(params.get("state")).toEqual(expect.any(String));
                expect(params.get("nonce")).toEqual(expect.any(String));
                expect(params.get("scope")).toEqual(
                  "openid profile email offline_access"
                );
              }
            })
          });

          const request = new NextRequest(
            new URL(
              process.env.NEXT_PUBLIC_BASE_PATH + "/auth/login",
              DEFAULT.appBaseUrl
            ),
            {
              method: "GET"
            }
          );

          const response = await authClient.handleLogin(request);
          expect(response.status).toEqual(307);
          expect(response.headers.get("Location")).not.toBeNull();

          const authorizationUrl = new URL(response.headers.get("Location")!);
          expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);
          // query parameters should only include the `request_uri` and not the standard auth params
          expect(authorizationUrl.searchParams.get("request_uri")).toEqual(
            DEFAULT.requestUri
          );
          expect(authorizationUrl.searchParams.get("client_id")).toEqual(
            DEFAULT.clientId
          );
        });
      });

      describe("custom parameters to the authorization server", async () => {
        it("should forward all custom parameters sent via the query parameters to PAR", async () => {
          const secret = await generateSecret(32);
          const transactionStore = new TransactionStore({
            secret
          });
          const sessionStore = new StatelessSessionStore({
            secret
          });

          // set custom parameters in the login URL which should not be forwarded to the authorization server (in PAR request)
          const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
          loginUrl.searchParams.set("ext-custom_param", "custom_value");
          loginUrl.searchParams.set("audience", "urn:mystore:api");
          const request = new NextRequest(loginUrl, {
            method: "GET"
          });

          const authClient = new AuthClient({
            transactionStore,
            sessionStore,
            domain: DEFAULT.domain,
            clientId: DEFAULT.clientId,
            clientSecret: DEFAULT.clientSecret,
            pushedAuthorizationRequests: true,
            secret,
            appBaseUrl: DEFAULT.appBaseUrl,

            routes: getDefaultRoutes(),
            fetch: getMockAuthorizationServer({
              onParRequest: async (request) => {
                const params = new URLSearchParams(await request.text());
                // With simplified approach, all custom parameters are now forwarded to PAR
                expect(params.get("ext-custom_param")).toEqual("custom_value");
                expect(params.get("audience")).toEqual("urn:mystore:api");
              }
            })
          });

          const response = await authClient.handleLogin(request);
          expect(response.status).toEqual(307);
          expect(response.headers.get("Location")).not.toBeNull();
          const authorizationUrl = new URL(response.headers.get("Location")!);
          expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);
          // query parameters should only include the `request_uri` and not the standard auth params
          expect(authorizationUrl.searchParams.get("request_uri")).toEqual(
            DEFAULT.requestUri
          );
          expect(authorizationUrl.searchParams.get("client_id")).toEqual(
            DEFAULT.clientId
          );
          expect(authorizationUrl.searchParams.get("redirect_uri")).toBeNull();
          expect(authorizationUrl.searchParams.get("response_type")).toBeNull();
          expect(
            authorizationUrl.searchParams.get("code_challenge")
          ).toBeNull();
          expect(
            authorizationUrl.searchParams.get("code_challenge_method")
          ).toBeNull();
          expect(authorizationUrl.searchParams.get("state")).toBeNull();
          expect(authorizationUrl.searchParams.get("nonce")).toBeNull();
          expect(authorizationUrl.searchParams.get("scope")).toBeNull();

          // transaction state
          const transactionCookies = response.cookies
            .getAll()
            .filter((c) => c.name.startsWith("__txn_"));
          expect(transactionCookies.length).toEqual(1);
          const transactionCookie = transactionCookies[0];
          const state = transactionCookie.name.replace("__txn_", "");
          expect(transactionCookie).toBeDefined();
          expect(
            (
              (await decrypt(
                transactionCookie.value,
                secret
              )) as jose.JWTDecryptResult
            ).payload
          ).toEqual(
            expect.objectContaining({
              nonce: expect.any(String),
              codeVerifier: expect.any(String),
              responseType: RESPONSE_TYPES.CODE,
              state,
              returnTo: "/"
            })
          );
        });

        it("should forward custom parameters set in the configuration to the authorization server", async () => {
          const secret = await generateSecret(32);
          const transactionStore = new TransactionStore({
            secret
          });
          const sessionStore = new StatelessSessionStore({
            secret
          });

          // set custom parameters in the login URL which should not be forwarded to the authorization server (in PAR request)
          const loginUrl = new URL("/auth/login", DEFAULT.appBaseUrl);
          const request = new NextRequest(loginUrl, {
            method: "GET"
          });

          const authClient = new AuthClient({
            transactionStore,
            sessionStore,
            domain: DEFAULT.domain,
            clientId: DEFAULT.clientId,
            clientSecret: DEFAULT.clientSecret,
            pushedAuthorizationRequests: true,
            secret,
            appBaseUrl: DEFAULT.appBaseUrl,

            routes: getDefaultRoutes(),
            authorizationParameters: {
              "ext-custom_param": "custom_value",
              audience: "urn:mystore:api"
            },
            fetch: getMockAuthorizationServer({
              onParRequest: async (request) => {
                const params = new URLSearchParams(await request.text());
                expect(params.get("ext-custom_param")).toEqual("custom_value");
                expect(params.get("audience")).toEqual("urn:mystore:api");
              }
            })
          });

          const response = await authClient.handleLogin(request);
          expect(response.status).toEqual(307);
          expect(response.headers.get("Location")).not.toBeNull();
          const authorizationUrl = new URL(response.headers.get("Location")!);
          expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);
          // query parameters should only include the `request_uri` and not the standard auth params
          expect(authorizationUrl.searchParams.get("request_uri")).toEqual(
            DEFAULT.requestUri
          );
          expect(authorizationUrl.searchParams.get("client_id")).toEqual(
            DEFAULT.clientId
          );
          expect(authorizationUrl.searchParams.get("redirect_uri")).toBeNull();
          expect(authorizationUrl.searchParams.get("response_type")).toBeNull();
          expect(
            authorizationUrl.searchParams.get("code_challenge")
          ).toBeNull();
          expect(
            authorizationUrl.searchParams.get("code_challenge_method")
          ).toBeNull();
          expect(authorizationUrl.searchParams.get("state")).toBeNull();
          expect(authorizationUrl.searchParams.get("nonce")).toBeNull();
          expect(authorizationUrl.searchParams.get("scope")).toBeNull();

          // transaction state
          const transactionCookies = response.cookies
            .getAll()
            .filter((c) => c.name.startsWith("__txn_"));
          expect(transactionCookies.length).toEqual(1);
          const transactionCookie = transactionCookies[0];
          const state = transactionCookie.name.replace("__txn_", "");
          expect(transactionCookie).toBeDefined();
          expect(
            (await decrypt(transactionCookie!.value, secret))!.payload
          ).toEqual(
            expect.objectContaining({
              nonce: expect.any(String),
              codeVerifier: expect.any(String),
              responseType: RESPONSE_TYPES.CODE,
              state,
              returnTo: "/"
            })
          );
        });
      });
    });

    describe("with custom callback route", async () => {
      it("should redirect to the custom callback route after login", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          fetch: getMockAuthorizationServer(),

          routes: {
            ...getDefaultRoutes(),
            callback: "/custom-callback"
          }
        });
        const request = new NextRequest(
          new URL("/auth/login", DEFAULT.appBaseUrl),
          {
            method: "GET"
          }
        );

        const response = await authClient.handleLogin(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

        // query parameters
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/custom-callback`
        );
      });
    });

    describe("with PAR enabled", async () => {
      it("should forward safe UI parameters like screen_hint even when PAR is enabled", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });

        // Mock PAR request to verify that safe parameters are sent
        let parRequestParams: URLSearchParams;
        const mockFetch = getMockAuthorizationServer({
          onParRequest: async (request) => {
            // Extract form data from PAR request body
            const formData = await request.text();
            parRequestParams = new URLSearchParams(formData);
          }
        });

        const authClient = new AuthClient({
          transactionStore,
          sessionStore,
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          pushedAuthorizationRequests: true,
          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          routes: getDefaultRoutes(),
          fetch: mockFetch
        });

        const loginUrl = new URL(
          "/auth/login?screen_hint=signup&scope=malicious",
          DEFAULT.appBaseUrl
        );
        const request = new NextRequest(loginUrl, {
          method: "GET"
        });

        const response = await authClient.handleLogin(request);
        const authorizationUrl = new URL(response.headers.get("Location")!);

        // With PAR, the authorization URL should only contain request_uri and client_id
        expect(authorizationUrl.searchParams.get("request_uri")).toBeTruthy();
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(
          DEFAULT.clientId
        );

        // But screen_hint should be sent in the PAR request (safe parameter)
        expect(parRequestParams!.get("screen_hint")).toEqual("signup");
        // With simplified approach, all parameters including scope are forwarded to PAR
        // The scope parameter should contain the query param value (not filtered)
        expect(parRequestParams!.get("scope")).toEqual("malicious");
      });

      it("should forward multiple safe parameters when PAR is enabled", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });

        // Mock PAR request to verify that safe parameters are sent
        let parRequestParams: URLSearchParams;
        const mockFetch = getMockAuthorizationServer({
          onParRequest: async (request) => {
            // Extract form data from PAR request body
            const formData = await request.text();
            parRequestParams = new URLSearchParams(formData);
          }
        });

        const authClient = new AuthClient({
          transactionStore,
          sessionStore,
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          pushedAuthorizationRequests: true,
          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          routes: getDefaultRoutes(),
          fetch: mockFetch
        });

        const loginUrl = new URL(
          "/auth/login?screen_hint=signup&login_hint=user@example.com&prompt=login&ui_locales=en",
          DEFAULT.appBaseUrl
        );
        const request = new NextRequest(loginUrl, {
          method: "GET"
        });

        await authClient.handleLogin(request);

        // All safe parameters should be sent in the PAR request
        expect(parRequestParams!.get("screen_hint")).toEqual("signup");
        expect(parRequestParams!.get("login_hint")).toEqual("user@example.com");
        expect(parRequestParams!.get("prompt")).toEqual("login");
        expect(parRequestParams!.get("ui_locales")).toEqual("en");
      });

      it("should forward custom parameters but protect internal security parameters", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });

        // Mock PAR request to verify that security parameters are not sent
        let parRequestParams: URLSearchParams;
        const mockFetch = getMockAuthorizationServer({
          onParRequest: async (request) => {
            // Extract form data from PAR request body
            const formData = await request.text();
            parRequestParams = new URLSearchParams(formData);
          }
        });

        const authClient = new AuthClient({
          transactionStore,
          sessionStore,
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          pushedAuthorizationRequests: true,
          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          routes: getDefaultRoutes(),
          fetch: mockFetch
        });

        const loginUrl = new URL(
          "/auth/login?scope=read:users&audience=https://api.example.com&redirect_uri=https://malicious.com&screen_hint=signup",
          DEFAULT.appBaseUrl
        );
        const request = new NextRequest(loginUrl, {
          method: "GET"
        });

        await authClient.handleLogin(request);

        // With simplified approach, custom parameters are forwarded to PAR
        expect(parRequestParams!.get("scope")).toEqual("read:users"); // Query param forwarded
        expect(parRequestParams!.get("audience")).toEqual(
          "https://api.example.com"
        ); // Query param forwarded
        expect(parRequestParams!.get("redirect_uri")).toEqual(
          `${DEFAULT.appBaseUrl}/auth/callback`
        );
        expect(parRequestParams!.get("screen_hint")).toEqual("signup"); // Query param forwarded
      });
    });
  });

  describe("handleLogout", async () => {
    it("should redirect to the authorization server logout URL with the correct params", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      // set the session cookie to assert it's been cleared
      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          idToken: DEFAULT.idToken,
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: 123456
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const response = await authClient.handleLogout(request);
      expect(response.status).toEqual(307);
      expect(response.headers.get("Location")).not.toBeNull();

      const authorizationUrl = new URL(response.headers.get("Location")!);
      expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

      // query parameters
      expect(authorizationUrl.searchParams.get("client_id")).toEqual(
        DEFAULT.clientId
      );
      expect(
        authorizationUrl.searchParams.get("post_logout_redirect_uri")
      ).toEqual(`${DEFAULT.appBaseUrl}`);
      expect(authorizationUrl.searchParams.get("logout_hint")).toEqual(
        DEFAULT.sid
      );
      expect(authorizationUrl.searchParams.get("id_token_hint")).toEqual(
        DEFAULT.idToken
      );

      // session cookie is cleared
      const cookie = response.cookies.get("__session");
      expect(cookie?.value).toEqual("");
      expect(cookie?.maxAge).toEqual(0);
    });

    it("should use the returnTo URL as the post_logout_redirect_uri if provided", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      // set the session cookie to assert it's been cleared
      const session: SessionData = {
        user: { sub: DEFAULT.sub },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: 123456
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const url = new URL("/auth/logout", DEFAULT.appBaseUrl);
      url.searchParams.set("returnTo", `${DEFAULT.appBaseUrl}/some-other-page`);
      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handleLogout(request);
      expect(response.status).toEqual(307);
      expect(response.headers.get("Location")).not.toBeNull();

      const authorizationUrl = new URL(response.headers.get("Location")!);
      expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

      // query parameters
      expect(authorizationUrl.searchParams.get("client_id")).toEqual(
        DEFAULT.clientId
      );
      expect(
        authorizationUrl.searchParams.get("post_logout_redirect_uri")
      ).toEqual(`${DEFAULT.appBaseUrl}/some-other-page`);
      expect(authorizationUrl.searchParams.get("logout_hint")).toEqual(
        DEFAULT.sid
      );

      // session cookie is cleared
      const cookie = response.cookies.get("__session");
      expect(cookie?.value).toEqual("");
      expect(cookie?.maxAge).toEqual(0);
    });

    it("should not include the id_token_hint parameter if a session does not exist", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleLogout(request);
      expect(response.status).toEqual(307);
      expect(response.headers.get("Location")).not.toBeNull();

      const authorizationUrl = new URL(response.headers.get("Location")!);
      expect(authorizationUrl.searchParams.get("id_token_hint")).toBeNull();
    });

    it("should not include the logout_hint parameter if a session does not exist", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleLogout(request);
      expect(response.status).toEqual(307);
      expect(response.headers.get("Location")).not.toBeNull();

      const authorizationUrl = new URL(response.headers.get("Location")!);
      expect(authorizationUrl.origin).toEqual(`https://${DEFAULT.domain}`);

      // query parameters
      expect(authorizationUrl.searchParams.get("client_id")).toEqual(
        DEFAULT.clientId
      );
      expect(
        authorizationUrl.searchParams.get("post_logout_redirect_uri")
      ).toEqual(`${DEFAULT.appBaseUrl}`);
      expect(authorizationUrl.searchParams.get("logout_hint")).toBeNull();

      // session cookie is cleared
      const cookie = response.cookies.get("__session");
      expect(cookie?.value).toEqual("");
      expect(cookie?.maxAge).toEqual(0);
    });

    it("should fallback to the /v2/logout endpoint if the client does not have RP-Initiated Logout enabled", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          discoveryResponse: Response.json(
            {
              ..._authorizationServerMetadata,
              end_session_endpoint: null
            },
            {
              status: 200,
              headers: {
                "content-type": "application/json"
              }
            }
          )
        })
      });

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleLogout(request);
      expect(response.status).toEqual(307);
      const logoutUrl = new URL(response.headers.get("Location")!);
      expect(logoutUrl.origin).toEqual(`https://${DEFAULT.domain}`);

      // query parameters
      expect(logoutUrl.searchParams.get("client_id")).toEqual(DEFAULT.clientId);
      expect(logoutUrl.searchParams.get("returnTo")).toEqual(
        DEFAULT.appBaseUrl
      );

      // session cookie is cleared
      const cookie = response.cookies.get("__session");
      expect(cookie?.value).toEqual("");
      expect(cookie?.maxAge).toEqual(0);
    });

    it("should return an error if the discovery endpoint could not be fetched", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          discoveryResponse: new Response(null, { status: 500 })
        })
      });

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleLogout(request);
      expect(response.status).toEqual(500);
      expect(await response.text()).toEqual(
        "An error occurred while trying to initiate the logout request."
      );
    });

    describe("includeIdTokenHintInOIDCLogoutUrl option", async () => {
      it("should include id_token_hint in OIDC logout URL when includeIdTokenHintInOIDCLogoutUrl is true (default)", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          includeIdTokenHintInOIDCLogoutUrl: true, // explicit true

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        // set the session cookie with id token
        const session: SessionData = {
          user: { sub: DEFAULT.sub },
          tokenSet: {
            idToken: DEFAULT.idToken,
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: 123456
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000)
          }
        };

        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const sessionCookie = await encrypt(session, secret, expiration);
        const headers = new Headers();
        headers.append("cookie", `__session=${sessionCookie}`);

        const request = new NextRequest(
          new URL("/auth/logout", DEFAULT.appBaseUrl),
          {
            method: "GET",
            headers
          }
        );

        const response = await authClient.handleLogout(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.searchParams.get("id_token_hint")).toEqual(
          DEFAULT.idToken
        );
        expect(authorizationUrl.searchParams.get("logout_hint")).toEqual(
          DEFAULT.sid
        );
      });

      it("should exclude id_token_hint from OIDC logout URL when includeIdTokenHintInOIDCLogoutUrl is false", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          includeIdTokenHintInOIDCLogoutUrl: false, // explicit false

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        // set the session cookie with id token
        const session: SessionData = {
          user: { sub: DEFAULT.sub },
          tokenSet: {
            idToken: DEFAULT.idToken,
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: 123456
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000)
          }
        };

        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const sessionCookie = await encrypt(session, secret, expiration);
        const headers = new Headers();
        headers.append("cookie", `__session=${sessionCookie}`);

        const request = new NextRequest(
          new URL("/auth/logout", DEFAULT.appBaseUrl),
          {
            method: "GET",
            headers
          }
        );

        const response = await authClient.handleLogout(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.searchParams.get("id_token_hint")).toBeNull();
        expect(authorizationUrl.searchParams.get("logout_hint")).toEqual(
          DEFAULT.sid
        );
      });

      it("should include id_token_hint by default when includeIdTokenHintInOIDCLogoutUrl is not specified", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          // includeIdTokenHintInOIDCLogoutUrl not specified, should default to true

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        // set the session cookie with id token
        const session: SessionData = {
          user: { sub: DEFAULT.sub },
          tokenSet: {
            idToken: DEFAULT.idToken,
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: 123456
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000)
          }
        };

        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const sessionCookie = await encrypt(session, secret, expiration);
        const headers = new Headers();
        headers.append("cookie", `__session=${sessionCookie}`);

        const request = new NextRequest(
          new URL("/auth/logout", DEFAULT.appBaseUrl),
          {
            method: "GET",
            headers
          }
        );

        const response = await authClient.handleLogout(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.searchParams.get("id_token_hint")).toEqual(
          DEFAULT.idToken
        );
      });

      it("should not include id_token_hint when session has no idToken, regardless of includeIdTokenHintInOIDCLogoutUrl setting", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,
          includeIdTokenHintInOIDCLogoutUrl: true, // even with true, no idToken means no hint

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        // set the session cookie without id token
        const session: SessionData = {
          user: { sub: DEFAULT.sub },
          tokenSet: {
            // idToken: undefined, // no idToken
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: 123456
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000)
          }
        };

        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const sessionCookie = await encrypt(session, secret, expiration);
        const headers = new Headers();
        headers.append("cookie", `__session=${sessionCookie}`);

        const request = new NextRequest(
          new URL("/auth/logout", DEFAULT.appBaseUrl),
          {
            method: "GET",
            headers
          }
        );

        const response = await authClient.handleLogout(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const authorizationUrl = new URL(response.headers.get("Location")!);
        expect(authorizationUrl.searchParams.get("id_token_hint")).toBeNull();
        expect(authorizationUrl.searchParams.get("logout_hint")).toEqual(
          DEFAULT.sid
        );
      });
    });
  });

  describe("handleProfile", async () => {
    it("should return the user attributes stored in the session", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      // set the session cookie to assert it's been cleared
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: 123456
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const request = new NextRequest(
        new URL("/auth/profile", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const response = await authClient.handleProfile(request);
      expect(response.status).toEqual(200);
      expect(await response.json()).toEqual({
        sub: DEFAULT.sub,
        name: "John Doe",
        email: "john@example.com",
        picture: "https://example.com/john.jpg"
      });
    });

    it("should return a 401 if the user is not authenticated", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const request = new NextRequest(
        new URL("/auth/profile", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleProfile(request);
      expect(response.status).toEqual(401);
      expect(response.body).toBeNull();
    });

    it("should return a 204 if the user is not authenticated and noContentProfileResponseWhenUnauthenticated is enabled", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer(),

        noContentProfileResponseWhenUnauthenticated: true
      });

      const request = new NextRequest(
        new URL("/auth/profile", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleProfile(request);
      expect(response.status).toEqual(204);
      expect(response.body).toBeNull();
    });
  });

  describe("handleCallback", async () => {
    it("should establish a session — happy path", async () => {
      const state = "transaction-state";
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const headers = new Headers();
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/dashboard"
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handleCallback(request);
      expect(response.status).toEqual(307);
      expect(response.headers.get("Location")).not.toBeNull();

      const redirectUrl = new URL(response.headers.get("Location")!);
      expect(redirectUrl.pathname).toEqual("/dashboard");

      // validate the session cookie
      const sessionCookie = response.cookies.get("__session");
      expect(sessionCookie).toBeDefined();
      const { payload: session } = (await decrypt(
        sessionCookie!.value,
        secret
      )) as jose.JWTDecryptResult;
      expect(session).toEqual(
        expect.objectContaining({
          user: {
            sub: DEFAULT.sub
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            idToken: expect.stringMatching(/^eyJhbGciOiJSUzI1NiJ9\..+\..+$/),
            expiresAt: expect.any(Number)
          },
          internal: {
            sid: expect.any(String),
            createdAt: expect.any(Number)
          }
        })
      );

      // validate the transaction cookie has been removed
      const transactionCookie = response.cookies.get(`__txn_${state}`);
      expect(transactionCookie).toBeDefined();
      expect(transactionCookie!.value).toEqual("");
      expect(transactionCookie!.maxAge).toEqual(0);
    });

    describe("when a base path is defined", async () => {
      beforeAll(() => {
        process.env.NEXT_PUBLIC_BASE_PATH = "/base-path";
      });

      afterAll(() => {
        delete process.env.NEXT_PUBLIC_BASE_PATH;
      });

      it("should generate a callback URL with the base path", async () => {
        const state = "transaction-state";
        const code = "auth-code";

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        const url = new URL(
          process.env.NEXT_PUBLIC_BASE_PATH + "/auth/callback",
          DEFAULT.appBaseUrl
        );
        url.searchParams.set("code", code);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CODE,
          state: state,
          returnTo: "/dashboard"
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/base-path/dashboard");
      });
    });

    it("must use private_key_jwt when a clientAssertionSigningKey is specified", async () => {
      function pemToArrayBuffer(pem: string) {
        const b64 = pem
          .replace("\n", "")
          .replace("-----BEGIN PRIVATE KEY-----", "")
          .replace("-----END PRIVATE KEY-----", "");

        const byteString = atob(b64);
        const byteArray = new Uint8Array(byteString.length);
        for (let i = 0; i < byteString.length; i++) {
          byteArray[i] = byteString.charCodeAt(i);
        }
        return byteArray;
      }

      const clientAssertionSigningKey = await crypto.subtle.importKey(
        "pkcs8",
        pemToArrayBuffer(DEFAULT.clientAssertionSigningKey),
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: { name: "SHA-256" } // or SHA-512
        },
        true,
        ["sign"]
      );

      const state = "transaction-state";
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientAssertionSigningKey: clientAssertionSigningKey,
        clientAssertionSigningAlg: "RS256",

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const headers = new Headers();
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/dashboard"
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handleCallback(request);
      expect(response.status).toEqual(307);
      expect(response.headers.get("Location")).not.toBeNull();

      const redirectUrl = new URL(response.headers.get("Location")!);
      expect(redirectUrl.pathname).toEqual("/dashboard");

      // validate the session cookie
      const sessionCookie = response.cookies.get("__session");
      expect(sessionCookie).toBeDefined();
      const { payload: session } = (await decrypt(
        sessionCookie!.value,
        secret
      )) as jose.JWTDecryptResult;
      expect(session).toEqual(
        expect.objectContaining({
          user: {
            sub: DEFAULT.sub
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            idToken: expect.any(String),
            refreshToken: DEFAULT.refreshToken,
            expiresAt: expect.any(Number)
          },
          internal: {
            sid: expect.any(String),
            createdAt: expect.any(Number)
          }
        })
      );

      // validate the transaction cookie has been removed
      const transactionCookie = response.cookies.get(`__txn_${state}`);
      expect(transactionCookie).toBeDefined();
      expect(transactionCookie!.value).toEqual("");
      expect(transactionCookie!.maxAge).toEqual(0);
    });

    it("should return an error if the state parameter is missing", async () => {
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);

      const request = new NextRequest(url, {
        method: "GET"
      });

      const response = await authClient.handleCallback(request);
      expect(response.status).toEqual(500);
      expect(await response.text()).toEqual("The state parameter is missing.");
    });

    it("should return an error if the transaction state could not be found", async () => {
      const state = "transaction-state";
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const headers = new Headers();
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/dashboard"
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      headers.set(
        "cookie",
        `__txn_does-not-exist=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handleCallback(request);
      expect(response.status).toEqual(500);
      expect(await response.text()).toEqual("The state parameter is invalid.");
    });

    it("should return an error when there is an error authorizing the user", async () => {
      const state = "transaction-state";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("error", "some-error-code");
      url.searchParams.set("error_description", "some-error-description");
      url.searchParams.set("state", state);

      const headers = new Headers();
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/dashboard"
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handleCallback(request);
      expect(response.status).toEqual(500);
      expect(await response.text()).toEqual(
        "An error occurred during the authorization flow."
      );
    });

    it("should return an error if there was an error during the code exchange", async () => {
      const state = "transaction-state";
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            error: "some-error-code",
            error_description: "some-error-description"
          }
        })
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const headers = new Headers();
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/dashboard"
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handleCallback(request);
      expect(response.status).toEqual(500);
      expect(await response.text()).toEqual(
        "An error occurred while trying to exchange the authorization code."
      );
    });

    it("should return an error if the discovery endpoint could not be fetched", async () => {
      const state = "transaction-state";
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          discoveryResponse: new Response(null, { status: 500 })
        })
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const headers = new Headers();
      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/dashboard"
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handleCallback(request);
      expect(response.status).toEqual(500);
      expect(await response.text()).toEqual(
        "Discovery failed for the OpenID Connect configuration."
      );
    });

    describe("onCallback hook", async () => {
      it("should be called with the session data if the session is established", async () => {
        const state = "transaction-state";
        const code = "auth-code";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/other-path", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("code", code);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CODE,
          state: state,
          returnTo: "/dashboard"
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);

        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        // validate the new response redirect
        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/other-path");

        const expectedSession = {
          user: {
            sub: DEFAULT.sub
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            idToken: expect.any(String),
            expiresAt: expect.any(Number)
          },
          internal: {
            sid: expect.any(String),
            createdAt: expect.any(Number)
          }
        };
        const expectedContext = {
          responseType: RESPONSE_TYPES.CODE,
          returnTo: transactionState.returnTo,
          appBaseUrl: DEFAULT.appBaseUrl
        };

        expect(mockOnCallback).toHaveBeenCalledWith(
          null,
          expectedContext,
          expectedSession
        );

        // validate the session cookie
        const sessionCookie = response.cookies.get("__session");
        expect(sessionCookie).toBeDefined();
        const { payload: session } = (await decrypt(
          sessionCookie!.value,
          secret
        )) as jose.JWTDecryptResult;
        expect(session).toEqual(expect.objectContaining(expectedSession));
      });

      it("should be called with an error if the state parameter is missing", async () => {
        const code = "auth-code";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/error-page", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("code", code);

        const request = new NextRequest(url, {
          method: "GET"
        });

        // validate the new response redirect
        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/error-page");

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {},
          null
        );
        expect(mockOnCallback.mock.calls[0][0].code).toEqual("missing_state");

        // validate the session cookie has not been set
        const sessionCookie = response.cookies.get("__session");
        expect(sessionCookie).toBeUndefined();
      });

      it("should be called with an error if the transaction state could not be found", async () => {
        const state = "transaction-state";
        const code = "auth-code";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/error-page", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("code", code);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CODE,
          state: state,
          returnTo: "/dashboard"
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_non-existent-state=${await encrypt(transactionState, secret, expiration)}`
        );
        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        // validate the new response redirect
        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/error-page");

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {},
          null
        );
        expect(mockOnCallback.mock.calls[0][0].code).toEqual("invalid_state");

        // validate the session cookie has not been set
        const sessionCookie = response.cookies.get("__session");
        expect(sessionCookie).toBeUndefined();
      });

      it("should be called with an error when there is an error authorizing the user", async () => {
        const state = "transaction-state";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/error-page", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("error", "some-error-code");
        url.searchParams.set("error_description", "some-error-description");
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CODE,
          state: state,
          returnTo: "/dashboard"
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        // validate the new response redirect
        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/error-page");

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {
            responseType: RESPONSE_TYPES.CODE,
            returnTo: transactionState.returnTo,
            appBaseUrl: DEFAULT.appBaseUrl
          },
          null
        );
        expect(mockOnCallback.mock.calls[0][0].code).toEqual(
          "authorization_error"
        );

        // validate the session cookie has not been set
        const sessionCookie = response.cookies.get("__session");
        expect(sessionCookie).toBeUndefined();
      });

      it("should be called with an error when there is an error performing the authorization code grant request", async () => {
        const state = "transaction-state";
        const code = "auth-code";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/error-page", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer({
            tokenEndpointFetchError: new Error("Timeout error")
          }),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("code", code);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CODE,
          state: state,
          returnTo: "/dashboard"
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        // validate the new response redirect
        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/error-page");

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {
            responseType: RESPONSE_TYPES.CODE,
            returnTo: transactionState.returnTo,
            appBaseUrl: DEFAULT.appBaseUrl
          },
          null
        );
        expect(mockOnCallback.mock.calls[0][0].code).toEqual(
          "authorization_code_grant_request_error"
        );
      });

      it("should be called with an error if there was an error during the code exchange", async () => {
        const state = "transaction-state";
        const code = "auth-code";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/error-page", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer({
            tokenEndpointResponse: {
              error: "some-error-code",
              error_description: "some-error-description"
            }
          }),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("code", code);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CODE,
          state: state,
          returnTo: "/dashboard"
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        // validate the new response redirect
        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/error-page");

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {
            responseType: RESPONSE_TYPES.CODE,
            returnTo: transactionState.returnTo,
            appBaseUrl: DEFAULT.appBaseUrl
          },
          null
        );
        expect(mockOnCallback.mock.calls[0][0].code).toEqual(
          "authorization_code_grant_error"
        );

        // validate the session cookie has not been set
        const sessionCookie = response.cookies.get("__session");
        expect(sessionCookie).toBeUndefined();
      });
    });

    describe("beforeSessionSaved hook", async () => {
      it("should be called with the correct arguments", async () => {
        const state = "transaction-state";
        const code = "auth-code";

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const mockBeforeSessionSaved = vi.fn().mockResolvedValue({
          user: {
            sub: DEFAULT.sub
          },
          internal: {
            sid: DEFAULT.sid,
            expiresAt: expect.any(Number)
          }
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          beforeSessionSaved: mockBeforeSessionSaved
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("code", code);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CODE,
          state: state,
          returnTo: "/dashboard"
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        await authClient.handleCallback(request);
        expect(mockBeforeSessionSaved).toHaveBeenCalledWith(
          {
            user: expect.objectContaining({
              sub: DEFAULT.sub
            }),
            tokenSet: {
              accessToken: DEFAULT.accessToken,
              refreshToken: DEFAULT.refreshToken,
              idToken: expect.any(String),
              expiresAt: expect.any(Number)
            },
            internal: {
              sid: expect.any(String),
              createdAt: expect.any(Number)
            }
          },
          expect.any(String)
        );
      });

      it("should use the return value of the hook as the session data", async () => {
        const state = "transaction-state";
        const code = "auth-code";

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          beforeSessionSaved: async (session) => {
            return {
              ...session,
              user: {
                sub: DEFAULT.sub,
                name: "John Doe",
                email: "john@example.com",
                custom: "value"
              }
            };
          }
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("code", code);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CODE,
          state: state,
          returnTo: "/dashboard"
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/dashboard");

        // validate the session cookie
        const sessionCookie = response.cookies.get("__session");
        expect(sessionCookie).toBeDefined();
        const { payload: session } = (await decrypt(
          sessionCookie!.value,
          secret
        )) as jose.JWTDecryptResult;
        expect(session).toEqual(
          expect.objectContaining({
            user: {
              sub: DEFAULT.sub,
              name: "John Doe",
              email: "john@example.com",
              custom: "value"
            },
            tokenSet: {
              accessToken: DEFAULT.accessToken,
              refreshToken: DEFAULT.refreshToken,
              idToken: expect.any(String),
              expiresAt: expect.any(Number)
            },
            internal: {
              sid: expect.any(String),
              createdAt: expect.any(Number)
            }
          })
        );
      });

      it("should not call the hook if the session is not established", async () => {
        const mockBeforeSessionSaved = vi.fn();

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          beforeSessionSaved: mockBeforeSessionSaved
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        const request = new NextRequest(url, {
          method: "GET"
        });

        await authClient.handleCallback(request);
        expect(mockBeforeSessionSaved).not.toHaveBeenCalled();
      });

      it("should not allow overwriting the internal session data", async () => {
        const state = "transaction-state";
        const code = "auth-code";

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          // @ts-expect-error intentionally testing invalid internal session data
          beforeSessionSaved: async (session) => {
            return {
              ...session,
              user: {
                sub: DEFAULT.sub,
                name: "John Doe",
                email: "john@example.com",
                custom: "value"
              },
              internal: null
            };
          }
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("code", code);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          nonce: "nonce-value",
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CODE,
          state: state,
          returnTo: "/dashboard"
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/dashboard");

        // validate the session cookie
        const sessionCookie = response.cookies.get("__session");
        expect(sessionCookie).toBeDefined();
        const { payload: session } = (await decrypt(
          sessionCookie!.value,
          secret
        )) as jose.JWTDecryptResult;
        expect(session).toEqual(
          expect.objectContaining({
            user: {
              sub: DEFAULT.sub,
              name: "John Doe",
              email: "john@example.com",
              custom: "value"
            },
            tokenSet: {
              accessToken: DEFAULT.accessToken,
              refreshToken: DEFAULT.refreshToken,
              idToken: expect.any(String),
              expiresAt: expect.any(Number)
            },
            internal: {
              sid: expect.any(String),
              createdAt: expect.any(Number)
            }
          })
        );
      });
    });

    describe("defaultOnCallback", async () => {
      it("should fall back to the single configured appBaseUrl when ctx.appBaseUrl is missing", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        const response = await (authClient as any).defaultOnCallback(null, {
          returnTo: "/dashboard"
        });
        const redirectUrl = new URL(response.headers.get("Location")!);

        expect(redirectUrl.toString()).toEqual(
          `${DEFAULT.appBaseUrl}/dashboard`
        );
      });

      it("should throw when appBaseUrl is missing from ctx and configuration", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        await expect(
          (authClient as any).defaultOnCallback(null, { returnTo: "/" })
        ).rejects.toThrow(InvalidConfigurationError);
      });
    });

    describe("connect account callback", async () => {
      it("should complete the connect account flow and call onCallback hook", async () => {
        const state = "transaction-state";
        const connectCode = "connect-code";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/dashboard", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer({
            onCompleteConnectAccountRequest: async (req) => {
              const completeConnectAccountRequestBody = await req.json();
              expect(completeConnectAccountRequestBody).toEqual(
                expect.objectContaining({
                  auth_session: DEFAULT.connectAccount.authSession,
                  connect_code: connectCode,
                  redirect_uri: `${DEFAULT.appBaseUrl}/auth/callback`,
                  code_verifier: "code-verifier"
                })
              );
            }
          }),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("connect_code", connectCode);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CONNECT_CODE,
          state: state,
          returnTo: "/dashboard",
          authSession: DEFAULT.connectAccount.authSession
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const session: SessionData = {
          user: {
            sub: DEFAULT.sub,
            name: "John Doe",
            email: "john@example.com",
            picture: "https://example.com/john.jpg"
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            scope: "openid profile email",
            refreshToken: DEFAULT.refreshToken,
            expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60 // expires in 10 days
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const sessionCookie = await encrypt(session, secret, expiration);
        headers.append("cookie", `__session=${sessionCookie}`);

        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/dashboard");

        // validate the transaction cookie has been removed
        const transactionCookie = response.cookies.get(`__txn_${state}`);
        expect(transactionCookie).toBeDefined();
        expect(transactionCookie!.value).toEqual("");
        expect(transactionCookie!.maxAge).toEqual(0);

        // validate that onCallback has been called with the connected account
        const expectedSession = expect.objectContaining({
          user: {
            sub: DEFAULT.sub,
            name: "John Doe",
            email: "john@example.com",
            picture: "https://example.com/john.jpg"
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            refreshToken: DEFAULT.refreshToken,
            expiresAt: expect.any(Number),
            scope: "openid profile email"
          },
          internal: {
            sid: expect.any(String),
            createdAt: expect.any(Number)
          }
        });
        const expectedContext = expect.objectContaining({
          responseType: RESPONSE_TYPES.CONNECT_CODE,
          returnTo: transactionState.returnTo,
          connectedAccount: {
            accessType: "offline",
            connection: "google-oauth2",
            createdAt: expect.any(String),
            expiresAt: expect.any(String),
            id: "cac_abc123",
            scopes: ["openid", "profile", "email"]
          }
        });

        // Here is an issue
        expect(mockOnCallback).toHaveBeenCalledWith(
          null,
          expectedContext,
          expectedSession
        );
      });

      it("should call handleCallbackError with an error if the user does not have a session", async () => {
        const state = "transaction-state";
        const connectCode = "connect-code";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/dashboard", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("connect_code", connectCode);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CONNECT_CODE,
          state: state,
          returnTo: "/dashboard",
          authSession: DEFAULT.connectAccount.authSession
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );

        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {
            responseType: RESPONSE_TYPES.CONNECT_CODE,
            returnTo: transactionState.returnTo,
            appBaseUrl: DEFAULT.appBaseUrl
          },
          null
        );
        expect(mockOnCallback.mock.calls[0][0].code).toEqual(
          ConnectAccountErrorCodes.MISSING_SESSION
        );
      });

      it("should call handleCallbackError with an error if there was an error fetching the token set", async () => {
        const state = "transaction-state";
        const connectCode = "connect-code";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/dashboard", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("connect_code", connectCode);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CONNECT_CODE,
          state: state,
          returnTo: "/dashboard",
          authSession: DEFAULT.connectAccount.authSession
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const session: SessionData = {
          user: {
            sub: DEFAULT.sub,
            name: "John Doe",
            email: "john@example.com",
            picture: "https://example.com/john.jpg"
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            scope: "openid profile email",
            refreshToken: DEFAULT.refreshToken,
            expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60 // expires in 10 days
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const sessionCookie = await encrypt(session, secret, expiration);
        headers.append("cookie", `__session=${sessionCookie}`);

        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        authClient.getTokenSet = vi
          .fn()
          .mockResolvedValue([
            new AccessTokenError(
              AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
              "No access token found and a refresh token was not provided. The user needs to re-authenticate."
            )
          ]);

        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/dashboard");

        // validate the transaction cookie has been removed
        const transactionCookie = response.cookies.get(`__txn_${state}`);
        expect(transactionCookie).toBeDefined();
        expect(transactionCookie!.value).toEqual("");
        expect(transactionCookie!.maxAge).toEqual(0);

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {
            responseType: RESPONSE_TYPES.CONNECT_CODE,
            returnTo: transactionState.returnTo,
            appBaseUrl: DEFAULT.appBaseUrl
          },
          null
        );
        expect(mockOnCallback.mock.calls[0][0].code).toEqual(
          AccessTokenErrorCode.MISSING_REFRESH_TOKEN
        );
      });

      it("should call handleCallbackError with an error if there was an error while calling the complete connect account endpoint", async () => {
        const state = "transaction-state";
        const connectCode = "connect-code";

        const mockOnCallback = vi
          .fn()
          .mockResolvedValue(
            NextResponse.redirect(new URL("/dashboard", DEFAULT.appBaseUrl))
          );

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer({
            completeConnectAccountErrorResponse: Response.json(
              {
                title: "Not Found",
                type: "https://auth0.com/api-errors/A0E-404-0001",
                detail: "Invalid or expired session",
                status: 404
              },
              {
                status: 404
              }
            )
          }),

          onCallback: mockOnCallback
        });

        const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
        url.searchParams.set("connect_code", connectCode);
        url.searchParams.set("state", state);

        const headers = new Headers();
        const transactionState: TransactionState = {
          maxAge: 3600,
          codeVerifier: "code-verifier",
          responseType: RESPONSE_TYPES.CONNECT_CODE,
          state: state,
          returnTo: "/dashboard",
          authSession: DEFAULT.connectAccount.authSession
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        headers.set(
          "cookie",
          `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
        );
        const session: SessionData = {
          user: {
            sub: DEFAULT.sub,
            name: "John Doe",
            email: "john@example.com",
            picture: "https://example.com/john.jpg"
          },
          tokenSet: {
            accessToken: DEFAULT.accessToken,
            scope: "openid profile email",
            refreshToken: DEFAULT.refreshToken,
            expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60 // expires in 10 days
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const sessionCookie = await encrypt(session, secret, expiration);
        headers.append("cookie", `__session=${sessionCookie}`);

        const request = new NextRequest(url, {
          method: "GET",
          headers
        });

        const response = await authClient.handleCallback(request);
        expect(response.status).toEqual(307);
        expect(response.headers.get("Location")).not.toBeNull();

        const redirectUrl = new URL(response.headers.get("Location")!);
        expect(redirectUrl.pathname).toEqual("/dashboard");

        // validate the transaction cookie has been removed
        const transactionCookie = response.cookies.get(`__txn_${state}`);
        expect(transactionCookie).toBeDefined();
        expect(transactionCookie!.value).toEqual("");
        expect(transactionCookie!.maxAge).toEqual(0);

        expect(mockOnCallback).toHaveBeenCalledWith(
          expect.any(Error),
          {
            responseType: RESPONSE_TYPES.CONNECT_CODE,
            returnTo: transactionState.returnTo,
            appBaseUrl: DEFAULT.appBaseUrl
          },
          null
        );
        expect(mockOnCallback.mock.calls[0][0].code).toEqual(
          ConnectAccountErrorCodes.FAILED_TO_COMPLETE
        );
      });
    });
  });

  describe("handleAccessToken", async () => {
    it("should return the access token if the user has a session", async () => {
      const currentAccessToken = DEFAULT.accessToken;
      const newAccessToken = "at_456";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            token_type: "Bearer",
            access_token: newAccessToken,
            scope: "openid profile email",
            expires_in: 86400 // expires in 10 days
          } as oauth.TokenEndpointResponse
        })
      });

      // we want to ensure the session is expired to return the refreshed access token
      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: currentAccessToken,
          scope: "openid profile email",
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const request = new NextRequest(
        new URL("/auth/access-token", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const response = await authClient.handleAccessToken(request);
      expect(response.status).toEqual(200);
      expect(await response.json()).toEqual({
        token: newAccessToken,
        scope: "openid profile email",
        expires_at: expect.any(Number),
        expires_in: expect.any(Number),
        token_type: "bearer"
      });

      // validate that the session cookie has been updated
      const updatedSessionCookie = response.cookies.get("__session");
      const { payload: updatedSession } = (await decrypt<SessionData>(
        updatedSessionCookie!.value,
        secret
      )) as jose.JWTDecryptResult<SessionData>;
      expect(updatedSession.tokenSet.accessToken).toEqual(newAccessToken);
    });

    it("should return expires_in based on server time", async () => {
      vi.useFakeTimers();
      const now = new Date("2026-01-01T00:00:00.000Z");
      vi.setSystemTime(now);

      try {
        const currentAccessToken = DEFAULT.accessToken;
        const newAccessToken = "at_456";
        const expiresIn = 3600;

        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer({
            tokenEndpointResponse: {
              token_type: "Bearer",
              access_token: newAccessToken,
              scope: "openid profile email",
              expires_in: expiresIn
            } as oauth.TokenEndpointResponse
          })
        });

        const expiresAt = Math.floor(now.getTime() / 1000) - 10 * 24 * 60 * 60; // expired
        const session: SessionData = {
          user: {
            sub: DEFAULT.sub,
            name: "John Doe",
            email: "john@example.com",
            picture: "https://example.com/john.jpg"
          },
          tokenSet: {
            accessToken: currentAccessToken,
            scope: "openid profile email",
            refreshToken: DEFAULT.refreshToken,
            expiresAt
          },
          internal: {
            sid: DEFAULT.sid,
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const sessionCookie = await encrypt(session, secret, expiration);
        const headers = new Headers();
        headers.append("cookie", `__session=${sessionCookie}`);
        const request = new NextRequest(
          new URL("/auth/access-token", DEFAULT.appBaseUrl),
          {
            method: "GET",
            headers
          }
        );

        const response = await authClient.handleAccessToken(request);
        expect(response.status).toEqual(200);
        const body = await response.json();
        const expectedExpiresAt = Math.floor(now.getTime() / 1000) + expiresIn;

        expect(body.expires_at).toEqual(expectedExpiresAt);
        expect(body.expires_in).toEqual(expiresIn);
      } finally {
        vi.useRealTimers();
      }
    });

    it("should return expires_in as 0 when expiresAt is missing", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const session = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          scope: "openid profile email"
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      } as SessionData;

      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const request = new NextRequest(
        new URL("/auth/access-token", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const response = await authClient.handleAccessToken(request);
      expect(response.status).toEqual(200);
      expect(await response.json()).toEqual({
        token: DEFAULT.accessToken,
        scope: "openid profile email",
        expires_at: 0,
        expires_in: 0
      });
    });

    it("should return a 401 if the user does not have a session", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const request = new NextRequest(
        new URL("/auth/access-token", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const response = await authClient.handleAccessToken(request);
      expect(response.status).toEqual(401);
      expect(await response.json()).toEqual({
        error: {
          message: "The user does not have an active session.",
          code: "missing_session"
        }
      });

      // validate that the session cookie has not been set
      const sessionCookie = response.cookies.get("__session");
      expect(sessionCookie).toBeUndefined();
    });

    it("should return an error if obtaining a token set failed", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expires in 10 days
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          // missing refresh token
          expiresAt
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const request = new NextRequest(
        new URL("/auth/access-token", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const response = await authClient.handleAccessToken(request);
      expect(response.status).toEqual(401);
      expect(await response.json()).toEqual({
        error: {
          message:
            "The access token has expired and a refresh token was not provided. The user needs to re-authenticate.",
          code: "missing_refresh_token"
        }
      });

      // validate that the session cookie has not been set
      expect(response.cookies.get("__session")).toBeUndefined();
    });
  });

  describe("handleBackChannelLogout", async () => {
    it("should return a 204 when successful — happy path", async () => {
      const deleteByLogoutTokenSpy = vi.fn();
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatefulSessionStore({
        secret,
        store: {
          get: vi.fn(),
          set: vi.fn(),
          delete: vi.fn(),
          deleteByLogoutToken: deleteByLogoutTokenSpy
        }
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer(),
        jwksCache: await getCachedJWKS()
      });

      const request = new NextRequest(
        new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: new URLSearchParams({
            logout_token: await generateLogoutToken({})
          })
        }
      );

      const response = await authClient.handleBackChannelLogout(request);
      expect(response.status).toEqual(204);
      expect(response.body).toBeNull();

      expect(deleteByLogoutTokenSpy).toHaveBeenCalledWith({
        sub: DEFAULT.sub,
        sid: DEFAULT.sid
      });
    });

    it("should return a 500 if a session store is not configured", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      // pass in a stateless session store that does not implement a store
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer(),
        jwksCache: await getCachedJWKS()
      });

      const request = new NextRequest(
        new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: new URLSearchParams({
            logout_token: await generateLogoutToken({})
          })
        }
      );

      const response = await authClient.handleBackChannelLogout(request);
      expect(response.status).toEqual(500);
      expect(await response.text()).toEqual(
        "A session data store is not configured."
      );
    });

    it("should return a 500 if a session store deleteByLogoutToken method is not implemented", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatefulSessionStore({
        secret,
        store: {
          get: vi.fn(),
          set: vi.fn(),
          delete: vi.fn()
        }
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer(),
        jwksCache: await getCachedJWKS()
      });

      const request = new NextRequest(
        new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
        {
          method: "POST",
          body: new URLSearchParams({
            logout_token: await generateLogoutToken({})
          })
        }
      );

      const response = await authClient.handleBackChannelLogout(request);
      expect(response.status).toEqual(500);
      expect(await response.text()).toEqual(
        "Back-channel logout is not supported by the session data store."
      );
    });

    describe("malformed logout tokens", async () => {
      it("should return a 400 if a logout token contains a nonce", async () => {
        const deleteByLogoutTokenSpy = vi.fn();
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy
          }
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS()
        });

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  nonce: "nonce-value" // nonce should NOT be present
                }
              })
            })
          }
        );

        const response = await authClient.handleBackChannelLogout(request);
        expect(response.status).toEqual(400);
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled();
      });

      it("should return a 400 if a logout token is not provided in the request", async () => {
        const deleteByLogoutTokenSpy = vi.fn();
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy
          }
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS()
        });

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({})
          }
        );

        const response = await authClient.handleBackChannelLogout(request);
        expect(response.status).toEqual(400);
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled();
      });

      it("should return a 400 if a logout token does not contain a sid nor sub", async () => {
        const deleteByLogoutTokenSpy = vi.fn();
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy
          }
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS()
        });

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  sid: null,
                  sub: null
                }
              })
            })
          }
        );

        const response = await authClient.handleBackChannelLogout(request);
        expect(response.status).toEqual(400);
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled();
      });

      it("should return a 400 if the sub claim is not a string", async () => {
        const deleteByLogoutTokenSpy = vi.fn();
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy
          }
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS()
        });

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  sub: 123
                }
              })
            })
          }
        );

        const response = await authClient.handleBackChannelLogout(request);
        expect(response.status).toEqual(400);
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled();
      });

      it("should return a 400 if the sid claim is not a string", async () => {
        const deleteByLogoutTokenSpy = vi.fn();
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy
          }
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS()
        });

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  sid: 123
                }
              })
            })
          }
        );

        const response = await authClient.handleBackChannelLogout(request);
        expect(response.status).toEqual(400);
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled();
      });

      it("should return a 400 if the events claim is missing", async () => {
        const deleteByLogoutTokenSpy = vi.fn();
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy
          }
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS()
        });

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  events: null
                }
              })
            })
          }
        );

        const response = await authClient.handleBackChannelLogout(request);
        expect(response.status).toEqual(400);
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled();
      });

      it("should return a 400 if the events object does not contain the backchannel logout member", async () => {
        const deleteByLogoutTokenSpy = vi.fn();
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy
          }
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS()
        });

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  events: {}
                }
              })
            })
          }
        );

        const response = await authClient.handleBackChannelLogout(request);
        expect(response.status).toEqual(400);
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled();
      });

      it("should return a 400 if the backchannel event is not an object", async () => {
        const deleteByLogoutTokenSpy = vi.fn();
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatefulSessionStore({
          secret,
          store: {
            get: vi.fn(),
            set: vi.fn(),
            delete: vi.fn(),
            deleteByLogoutToken: deleteByLogoutTokenSpy
          }
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),
          jwksCache: await getCachedJWKS()
        });

        const request = new NextRequest(
          new URL("/auth/backchannel-logout", DEFAULT.appBaseUrl),
          {
            method: "POST",
            body: new URLSearchParams({
              logout_token: await generateLogoutToken({
                claims: {
                  events: {
                    "http://schemas.openid.net/event/backchannel-logout":
                      "some string"
                  }
                }
              })
            })
          }
        );

        const response = await authClient.handleBackChannelLogout(request);
        expect(response.status).toEqual(400);
        expect(deleteByLogoutTokenSpy).not.toHaveBeenCalled();
      });
    });
  });

  describe("handleConnectAccount", async () => {
    it("should create a connected account request, persist the transaction state, and redirect the user", async () => {
      const currentAccessToken = DEFAULT.accessToken;
      const newAccessToken = "at_456";
      const secret = await generateSecret(32);
      let connectAccountRequestBody: any;
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            token_type: "Bearer",
            access_token: newAccessToken,
            scope:
              "openid profile email offline_access create:me:connected_accounts",
            expires_in: 86400 // expires in 10 days
          } as oauth.TokenEndpointResponse,
          onConnectAccountRequest: async (req) => {
            connectAccountRequestBody = await req.json();
            expect(connectAccountRequestBody).toEqual(
              expect.objectContaining({
                connection: DEFAULT.connectAccount.connection,
                redirect_uri: `${DEFAULT.appBaseUrl}/auth/callback`,
                state: expect.any(String),
                code_challenge: expect.any(String),
                code_challenge_method: "S256",
                scopes: [
                  "openid",
                  "profile",
                  "email",
                  "offline_access",
                  "read:messages"
                ],
                authorization_params: expect.objectContaining({
                  audience: "urn:some-audience"
                })
              })
            );
          }
        }),

        enableConnectAccountEndpoint: true
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: currentAccessToken,
          scope: "openid profile email",
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const url = new URL("/auth/connect", DEFAULT.appBaseUrl);
      url.searchParams.append("connection", DEFAULT.connectAccount.connection);
      url.searchParams.append("returnTo", "/some-url");
      url.searchParams.append("audience", "urn:some-audience");
      url.searchParams.append("scopes", "openid");
      url.searchParams.append("scopes", "profile");
      url.searchParams.append("scopes", "email");
      url.searchParams.append("scopes", "offline_access");
      url.searchParams.append("scopes", "read:messages");

      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handler(request);
      expect(response.status).toEqual(307);
      const connectUrl = new URL(response.headers.get("location")!);
      expect(connectUrl.origin).toEqual(`https://${DEFAULT.domain}`);
      expect(connectUrl.pathname).toEqual("/connect");
      expect(connectUrl.searchParams.get("ticket")).toEqual(
        DEFAULT.connectAccount.ticket
      );

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${connectAccountRequestBody.state}`
      );
      expect(transactionCookie).toBeDefined();
      expect(
        (
          (await decrypt(
            transactionCookie!.value,
            secret
          )) as jose.JWTDecryptResult
        ).payload
      ).toEqual(
        expect.objectContaining({
          responseType: RESPONSE_TYPES.CONNECT_CODE,
          state: connectAccountRequestBody?.state,
          returnTo: "/some-url",
          codeVerifier: expect.any(String),
          authSession: DEFAULT.connectAccount.authSession
        })
      );

      // validate that the session cookie has been updated
      const updatedSessionCookie = response.cookies.get("__session");
      const { payload: updatedSession } = (await decrypt<SessionData>(
        updatedSessionCookie!.value,
        secret
      )) as jose.JWTDecryptResult<SessionData>;
      const mrrtTokenSet = updatedSession.accessTokens?.find(
        (at) => at.audience === `https://${DEFAULT.domain}/me/`
      );
      expect(mrrtTokenSet).toBeDefined();
      expect(mrrtTokenSet?.accessToken).toEqual(newAccessToken);
      expect(mrrtTokenSet?.requestedScope).toEqual(
        "openid profile email offline_access create:me:connected_accounts"
      );
      expect(mrrtTokenSet?.scope).toEqual(
        "openid profile email offline_access create:me:connected_accounts"
      );
    });

    it("should sanitize the returnTo URL", async () => {
      const currentAccessToken = DEFAULT.accessToken;
      const newAccessToken = "at_456";
      const secret = await generateSecret(32);
      let connectAccountRequestBody: any;
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            token_type: "Bearer",
            access_token: newAccessToken,
            scope: "openid profile email",
            expires_in: 86400 // expires in 10 days
          } as oauth.TokenEndpointResponse,
          onConnectAccountRequest: async (req) => {
            connectAccountRequestBody = await req.json();
            expect(connectAccountRequestBody).toEqual(
              expect.objectContaining({
                connection: "some-connection",
                redirect_uri: `${DEFAULT.appBaseUrl}/auth/callback`,
                state: expect.any(String),
                code_challenge: expect.any(String),
                code_challenge_method: "S256",
                scopes: [
                  "openid",
                  "profile",
                  "email",
                  "offline_access",
                  "read:messages"
                ],
                authorization_params: expect.objectContaining({
                  audience: "urn:some-audience"
                })
              })
            );
          }
        }),

        enableConnectAccountEndpoint: true
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: currentAccessToken,
          scope: "openid profile email",
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const url = new URL("/auth/connect", DEFAULT.appBaseUrl);
      url.searchParams.append("connection", "some-connection");
      url.searchParams.append("returnTo", "https://google.com/some-url");
      url.searchParams.append("audience", "urn:some-audience");
      url.searchParams.append("scopes", "openid");
      url.searchParams.append("scopes", "profile");
      url.searchParams.append("scopes", "email");
      url.searchParams.append("scopes", "offline_access");
      url.searchParams.append("scopes", "read:messages");

      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handler(request);
      expect(response.status).toEqual(307);
      const connectUrl = new URL(response.headers.get("location")!);
      expect(connectUrl.origin).toEqual(`https://${DEFAULT.domain}`);
      expect(connectUrl.pathname).toEqual("/connect");
      expect(connectUrl.searchParams.get("ticket")).toEqual(
        DEFAULT.connectAccount.ticket
      );

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${connectAccountRequestBody.state}`
      );
      expect(transactionCookie).toBeDefined();
      expect(
        (
          (await decrypt(
            transactionCookie!.value,
            secret
          )) as jose.JWTDecryptResult
        ).payload
      ).toEqual(
        expect.objectContaining({
          responseType: RESPONSE_TYPES.CONNECT_CODE,
          state: connectAccountRequestBody?.state,
          returnTo: "/",
          codeVerifier: expect.any(String),
          authSession: DEFAULT.connectAccount.authSession
        })
      );
    });

    it("should not call the connect account handler if the endpoint is not enabled", async () => {
      const currentAccessToken = DEFAULT.accessToken;
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer(),

        enableConnectAccountEndpoint: false
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: currentAccessToken,
          scope: "openid profile email",
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const url = new URL("/auth/connect", DEFAULT.appBaseUrl);
      url.searchParams.append("connection", "some-connection");
      url.searchParams.append("returnTo", "/some-url");
      url.searchParams.append("audience", "urn:some-audience");
      url.searchParams.append("scopes", "openid");
      url.searchParams.append("scopes", "profile");
      url.searchParams.append("scopes", "email");
      url.searchParams.append("scopes", "offline_access");
      url.searchParams.append("scopes", "read:messages");

      authClient.handleConnectAccount = vi.fn();
      expect(authClient.handleConnectAccount).not.toHaveBeenCalled();
    });

    it("should return a 401 if the user does not have a session", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer(),

        enableConnectAccountEndpoint: true
      });

      const headers = new Headers();
      const url = new URL("/auth/connect", DEFAULT.appBaseUrl);
      url.searchParams.append("connection", "some-connection");
      url.searchParams.append("returnTo", "/some-url");
      url.searchParams.append("audience", "urn:some-audience");
      url.searchParams.append("scopes", "openid");
      url.searchParams.append("scopes", "profile");
      url.searchParams.append("scopes", "email");
      url.searchParams.append("scopes", "offline_access");
      url.searchParams.append("scopes", "read:messages");

      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handler(request);
      expect(response.status).toEqual(401);
    });

    it("should return a 400 if the connection query parameter is missing", async () => {
      const currentAccessToken = DEFAULT.accessToken;
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer(),

        enableConnectAccountEndpoint: true
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: currentAccessToken,
          scope: "openid profile email",
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const url = new URL("/auth/connect", DEFAULT.appBaseUrl);

      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handler(request);
      expect(response.status).toEqual(400);
    });

    it("should return a 401 if obtaining a token set failed", async () => {
      const currentAccessToken = DEFAULT.accessToken;
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer(),

        enableConnectAccountEndpoint: true
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: currentAccessToken,
          scope: "openid profile email",
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const url = new URL("/auth/connect", DEFAULT.appBaseUrl);
      url.searchParams.append("connection", "some-connection");
      url.searchParams.append("returnTo", "/some-url");
      url.searchParams.append("audience", "urn:some-audience");
      url.searchParams.append("scopes", "openid");
      url.searchParams.append("scopes", "profile");
      url.searchParams.append("scopes", "email");
      url.searchParams.append("scopes", "offline_access");
      url.searchParams.append("scopes", "read:messages");

      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      authClient.getTokenSet = vi
        .fn()
        .mockResolvedValue([new Error("some error"), null]);

      const response = await authClient.handler(request);
      expect(response.status).toEqual(401);
    });

    it("should forward the My Account API status code if an error occurs calling connectAccount", async () => {
      const currentAccessToken = DEFAULT.accessToken;
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer(),

        enableConnectAccountEndpoint: true
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: currentAccessToken,
          scope: "openid profile email",
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const url = new URL("/auth/connect", DEFAULT.appBaseUrl);
      url.searchParams.append("connection", "some-connection");
      url.searchParams.append("returnTo", "/some-url");
      url.searchParams.append("audience", "urn:some-audience");
      url.searchParams.append("scopes", "openid");
      url.searchParams.append("scopes", "profile");
      url.searchParams.append("scopes", "email");
      url.searchParams.append("scopes", "offline_access");
      url.searchParams.append("scopes", "read:messages");

      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      authClient.connectAccount = vi.fn().mockResolvedValue([
        new ConnectAccountError({
          code: ConnectAccountErrorCodes.FAILED_TO_INITIATE,
          message: "some message",
          cause: new MyAccountApiError({
            title: "Validation Error",
            type: "https://auth0.com/api-errors/A0E-400-0003",
            detail: "Invalid request payload input",
            status: 400,
            validationErrors: [
              {
                pointer: "",
                detail: "data must have required property 'connection'"
              }
            ]
          })
        }),
        null
      ]);

      const response = await authClient.handler(request);
      expect(response.status).toEqual(400);
    });

    it("should only forward the scopes if at least one scope is requested", async () => {
      const currentAccessToken = DEFAULT.accessToken;
      const newAccessToken = "at_456";
      const secret = await generateSecret(32);
      let connectAccountRequestBody: any;
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            token_type: "Bearer",
            access_token: newAccessToken,
            scope: "openid profile email offline_access",
            expires_in: 86400 // expires in 10 days
          } as oauth.TokenEndpointResponse,
          onConnectAccountRequest: async (req) => {
            connectAccountRequestBody = await req.json();
            expect(connectAccountRequestBody.scopes).toBeUndefined();
          }
        }),

        enableConnectAccountEndpoint: true
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
      const session: SessionData = {
        user: {
          sub: DEFAULT.sub,
          name: "John Doe",
          email: "john@example.com",
          picture: "https://example.com/john.jpg"
        },
        tokenSet: {
          accessToken: currentAccessToken,
          scope: "openid profile email",
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        },
        internal: {
          sid: DEFAULT.sid,
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(session, secret, expiration);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);
      const url = new URL("/auth/connect", DEFAULT.appBaseUrl);
      url.searchParams.append("connection", DEFAULT.connectAccount.connection);
      url.searchParams.append("returnTo", "/some-url");
      url.searchParams.append("audience", "urn:some-audience");

      const request = new NextRequest(url, {
        method: "GET",
        headers
      });

      const response = await authClient.handler(request);
      expect(response.status).toEqual(307);
      const connectUrl = new URL(response.headers.get("location")!);
      expect(connectUrl.origin).toEqual(`https://${DEFAULT.domain}`);
      expect(connectUrl.pathname).toEqual("/connect");
      expect(connectUrl.searchParams.get("ticket")).toEqual(
        DEFAULT.connectAccount.ticket
      );

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${connectAccountRequestBody.state}`
      );
      expect(transactionCookie).toBeDefined();
      expect(
        (
          (await decrypt(
            transactionCookie!.value,
            secret
          )) as jose.JWTDecryptResult
        ).payload
      ).toEqual(
        expect.objectContaining({
          responseType: RESPONSE_TYPES.CONNECT_CODE,
          state: connectAccountRequestBody?.state,
          returnTo: "/some-url",
          codeVerifier: expect.any(String),
          authSession: DEFAULT.connectAccount.authSession
        })
      );
    });
  });

  describe("getTokenSet", async () => {
    it("should return the access token if it has not expired", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt
      };

      const [error, updatedTokenSet] = await authClient.getTokenSet(
        createSessionData({ tokenSet })
      );
      expect(error).toBeNull();
      expect(updatedTokenSet?.tokenSet).toEqual(tokenSet);
    });

    it("should return an error if the token set does not contain a refresh token and the access token has expired", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        expiresAt
      };

      const [error, updatedTokenSet] = await authClient.getTokenSet(
        createSessionData({ tokenSet })
      );
      expect(error?.code).toEqual("missing_refresh_token");
      expect(updatedTokenSet).toBeNull();
    });

    it("should refresh the access token if it expired", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            token_type: "Bearer",
            access_token: DEFAULT.accessToken,
            expires_in: 86400, // expires in 10 days
            scope: "openid profile email offline_access"
          } as oauth.TokenEndpointResponse
        })
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt
      };

      const [error, updatedTokenSet] = await authClient.getTokenSet(
        createSessionData({ tokenSet })
      );
      expect(error).toBeNull();
      expect(updatedTokenSet?.tokenSet).toEqual({
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt: expect.any(Number),
        scope: "openid profile email offline_access",
        requestedScope: "openid profile email offline_access",
        audience: undefined,
        idToken: undefined,
        token_type: "bearer"
      });
    });

    it("should return an error if an error occurred during the refresh token exchange", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointResponse: {
            error: "some-error-code",
            error_description: "some-error-description"
          }
        })
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt
      };

      const [error, updatedTokenSet] = await authClient.getTokenSet(
        createSessionData({ tokenSet })
      );
      expect(error?.code).toEqual("failed_to_refresh_token");
      expect(updatedTokenSet).toBeNull();
    });

    it("should return an error if the discovery endpoint could not be fetched", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          discoveryResponse: new Response(null, { status: 500 })
        })
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt
      };

      const [error, updatedTokenSet] = await authClient.getTokenSet(
        createSessionData({ tokenSet })
      );
      expect(error?.code).toEqual("discovery_error");
      expect(updatedTokenSet).toBeNull();
    });

    describe("rotating refresh token", async () => {
      it("should refresh the access token if it expired along with the updated refresh token", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer({
            tokenEndpointResponse: {
              token_type: "Bearer",
              access_token: DEFAULT.accessToken,
              refresh_token: "rt_456",
              expires_in: 86400, // expires in 10 days,
              scope: "openid profile email offline_access"
            } as oauth.TokenEndpointResponse
          })
        });

        const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        };

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet })
        );
        expect(error).toBeNull();
        expect(updatedTokenSet?.tokenSet).toEqual({
          accessToken: DEFAULT.accessToken,
          refreshToken: "rt_456",
          expiresAt: expect.any(Number),
          requestedScope: "openid profile email offline_access",
          scope: "openid profile email offline_access",
          audience: undefined,
          idToken: undefined,
          token_type: "bearer"
        });
      });
    });

    describe("when audience or scope are provided", () => {
      it("should return the access token if it has not expired", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        };
        const accessTokens: AccessTokenSet[] = [
          {
            accessToken: "<access_token_1",
            expiresAt,
            audience: "https://api.example.com",
            scope: "openid profile email offline_access read:messages"
          },
          {
            accessToken: "access_token_2",
            expiresAt,
            audience: "https://api.example.com",
            scope: "openid profile email offline_access write:messages"
          }
        ];

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet, accessTokens }),
          { scope: "write:messages", audience: "https://api.example.com" }
        );
        expect(error).toBeNull();
        expect(updatedTokenSet?.tokenSet).toEqual({
          accessToken: "access_token_2",
          expiresAt,
          audience: "https://api.example.com",
          scope: "openid profile email offline_access write:messages",
          refreshToken: DEFAULT.refreshToken
        });
      });

      it("should return the access token when using map-based scope configuration and the access token has not expired", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer(),
          authorizationParameters: {
            audience: "custom_audience",
            scope: {
              custom_audience: "openid custom:default_scope"
            }
          }
        });

        const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        };
        const accessTokens: AccessTokenSet[] = [
          {
            accessToken: "<access_token_1",
            expiresAt,
            audience: "https://api.example.com",
            scope: "custom:default_scope read:messages"
          },
          {
            accessToken: "access_token_2",
            expiresAt,
            audience: "https://api.example.com",
            scope: "custom:default_scope write:messages"
          }
        ];

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet, accessTokens }),
          { scope: "write:messages", audience: "https://api.example.com" }
        );
        expect(error).toBeNull();
        expect(updatedTokenSet?.tokenSet).toEqual({
          accessToken: "access_token_2",
          expiresAt,
          audience: "https://api.example.com",
          scope: "custom:default_scope write:messages",
          refreshToken: DEFAULT.refreshToken
        });
      });

      it("should return an error if the token set does not contain a refresh token and the access token has expired", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60
        };

        const accessTokens: AccessTokenSet[] = [
          {
            accessToken: "<access_token_1",
            expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60,
            audience: "https://api.example.com",
            scope: "read:messages"
          },
          {
            accessToken: "access_token_2",
            expiresAt,
            audience: "https://api.example.com",
            scope: "write:messages"
          }
        ];

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet, accessTokens }),
          { scope: "write:messages", audience: "https://api.example.com" }
        );

        expect(error?.code).toEqual("missing_refresh_token");
        expect(updatedTokenSet).toBeNull();
      });

      it("should return an error if the token set does not contain a refresh token and the access token can not be found", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60
        };

        const accessTokens: AccessTokenSet[] = [
          {
            accessToken: "<access_token_1",
            expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60,
            audience: "https://api.example.com",
            scope: "read:messages"
          }
        ];

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet, accessTokens }),
          { scope: "write:messages", audience: "https://api.example.com" }
        );

        expect(error?.code).toEqual("missing_refresh_token");
        expect(updatedTokenSet).toBeNull();
      });

      it("should refresh the access token if it expired", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer({
            tokenEndpointResponse: {
              token_type: "Bearer",
              access_token: DEFAULT.accessToken,
              expires_in: 86400, // expires in 10 days
              scope: "write:messages"
            } as oauth.TokenEndpointResponse
          })
        });

        const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60,
          scope: "write:messages"
        };

        const accessTokens: AccessTokenSet[] = [
          {
            accessToken: "<access_token_1",
            expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60,
            audience: "https://api.example.com",
            scope: "read:messages openid profile email offline_access"
          },
          {
            accessToken: "access_token_2",
            expiresAt,
            audience: "https://api.example.com",
            scope: "openid profile email offline_access write:messages"
          }
        ];

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet, accessTokens }),
          { scope: "write:messages", audience: "https://api.example.com" }
        );
        expect(error).toBeNull();
        expect(updatedTokenSet?.tokenSet).toEqual({
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: expect.any(Number),
          scope: "write:messages",
          requestedScope: "openid profile email offline_access write:messages",
          audience: "https://api.example.com",
          idToken: undefined,
          token_type: "bearer"
        });
      });

      it("should request the access token if no audience provided", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer({
            tokenEndpointResponse: {
              token_type: "Bearer",
              access_token: "<access_token_3>",
              expires_in: 86400, // expires in 10 days,
              scope: "write:messages"
            } as oauth.TokenEndpointResponse
          })
        });

        const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60
        };

        const accessTokens: AccessTokenSet[] = [
          {
            accessToken: "<access_token_1",
            expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60,
            audience: "https://api.example.com",
            scope: "read:messages"
          },
          {
            accessToken: "access_token_2",
            expiresAt,
            audience: "https://api.example.com",
            scope: "write:messages"
          }
        ];

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet, accessTokens }),
          { scope: "write:messages" }
        );
        expect(error).toBeNull();
        expect(updatedTokenSet?.tokenSet).toEqual({
          accessToken: "<access_token_3>",
          refreshToken: DEFAULT.refreshToken,
          expiresAt: expect.any(Number),
          scope: "write:messages",
          requestedScope: "openid profile email offline_access write:messages",
          audience: undefined,
          idToken: undefined,
          token_type: "bearer"
        });
      });

      it("should request the access token if no audience provided", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          authorizationParameters: {
            audience: "audience",
            scope: {
              audience: "openid profile email offline_access"
            }
          },

          fetch: getMockAuthorizationServer({
            tokenEndpointResponse: {
              token_type: "Bearer",
              access_token: "<access_token_3>",
              expires_in: 86400, // expires in 10 days,
              scope: "write:messages"
            } as oauth.TokenEndpointResponse
          })
        });

        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60
        };

        const accessTokens: AccessTokenSet[] = [
          {
            accessToken: "access_token_2",
            expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60,
            audience: "audience-1",
            scope: "write:messages",
            requestedScope: ""
          }
        ];

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet, accessTokens }),
          { audience: "audience-1" }
        );
        expect(error).toBeNull();
        expect(updatedTokenSet?.tokenSet).toEqual({
          accessToken: "access_token_2",
          refreshToken: DEFAULT.refreshToken,
          expiresAt: expect.any(Number),
          scope: "write:messages",
          requestedScope: "",
          audience: "audience-1"
          //requestedScope: "openid profile email offline_access write:messages"
        });
      });

      it("should return an error if an error occurred during the refresh token exchange", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer({
            tokenEndpointResponse: {
              error: "some-error-code",
              error_description: "some-error-description"
            }
          })
        });

        const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60
        };

        const accessTokens: AccessTokenSet[] = [
          {
            accessToken: "<access_token_1",
            expiresAt: Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60,
            audience: "https://api.example.com",
            scope: "read:messages"
          },
          {
            accessToken: "access_token_2",
            expiresAt,
            audience: "https://api.example.com",
            scope: "write:messages"
          }
        ];

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet, accessTokens }),
          { scope: "write:messages", audience: "https://api.example.com" }
        );

        expect(error?.code).toEqual("failed_to_refresh_token");
        expect(updatedTokenSet).toBeNull();
      });

      it("should return the access token if it has not expired when only the audience is specified", async () => {
        const secret = await generateSecret(32);
        const transactionStore = new TransactionStore({
          secret
        });
        const sessionStore = new StatelessSessionStore({
          secret
        });
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,

          authorizationParameters: {
            audience: "https://default.example.com",
            scope: {
              "https://default.example.com": DEFAULT_SCOPES
            }
          },

          secret,
          appBaseUrl: DEFAULT.appBaseUrl,

          routes: getDefaultRoutes(),

          fetch: getMockAuthorizationServer()
        });

        const expiresAt = Math.floor(Date.now() / 1000) + 10 * 24 * 60 * 60; // expires in 10 days
        const tokenSet = {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt
        };
        const accessTokens: AccessTokenSet[] = [
          {
            accessToken: "<access_token_1>",
            expiresAt,
            audience: "https://api.example.com",
            // The default scope for this audience is empty
            requestedScope: "",
            scope: "read:messages"
          },
          {
            accessToken: "<access_token_2>",
            expiresAt,
            audience: "https://api.example.com",
            scope: "openid profile email offline_access write:messages"
          }
        ];

        const [error, updatedTokenSet] = await authClient.getTokenSet(
          createSessionData({ tokenSet, accessTokens }),
          { audience: "https://api.example.com" }
        );
        expect(error).toBeNull();
        expect(updatedTokenSet?.tokenSet).toEqual({
          accessToken: "<access_token_1>",
          expiresAt,
          audience: "https://api.example.com",
          refreshToken: DEFAULT.refreshToken,
          requestedScope: "",
          scope: "read:messages"
        });
      });
    });
  });

  describe("startInteractiveLogin", async () => {
    const createAuthClient = async ({
      pushedAuthorizationRequests = false,
      signInReturnToPath = "/",
      authorizationParameters = {}
    } = {}) => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });

      return new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        signInReturnToPath,
        pushedAuthorizationRequests,
        authorizationParameters: {
          scope: "openid profile email",
          ...authorizationParameters
        },

        fetch: getMockAuthorizationServer()
      });
    };

    it("should use the default returnTo path when no returnTo is provided", async () => {
      const defaultReturnTo = "/default-path";
      const authClient = await createAuthClient({
        signInReturnToPath: defaultReturnTo
      });

      // Mock the transactionStore.save method to verify the saved state
      const originalSave = authClient["transactionStore"].save;
      authClient["transactionStore"].save = vi.fn(
        async (cookies, state, reqCookies) => {
          expect(state.returnTo).toBe(defaultReturnTo);
          return originalSave.call(
            authClient["transactionStore"],
            cookies,
            state,
            reqCookies
          );
        }
      );

      await authClient.startInteractiveLogin();

      expect(authClient["transactionStore"].save).toHaveBeenCalled();
    });

    it("should sanitize and use the provided returnTo parameter", async () => {
      const authClient = await createAuthClient();
      const returnTo = "/custom-return-path";

      // Mock the transactionStore.save method to verify the saved state
      const originalSave = authClient["transactionStore"].save;
      authClient["transactionStore"].save = vi.fn(
        async (cookies, state, reqCookies) => {
          expect(state.returnTo).toBe("/custom-return-path");
          return originalSave.call(
            authClient["transactionStore"],
            cookies,
            state,
            reqCookies
          );
        }
      );

      await authClient.startInteractiveLogin({ returnTo });

      expect(authClient["transactionStore"].save).toHaveBeenCalled();
    });

    it("should sanitize and use the provided returnTo parameter — absolute URL", async () => {
      const authClient = await createAuthClient();
      const returnTo =
        DEFAULT.appBaseUrl + "/custom-return-path?query=param#hash";

      const originalSave = authClient["transactionStore"].save;
      authClient["transactionStore"].save = vi.fn(
        async (cookies, state, reqCookies) => {
          expect(state.returnTo).toBe("/custom-return-path?query=param#hash");
          return originalSave.call(
            authClient["transactionStore"],
            cookies,
            state,
            reqCookies
          );
        }
      );

      await authClient.startInteractiveLogin({ returnTo });

      expect(authClient["transactionStore"].save).toHaveBeenCalled();
    });

    it("should reject unsafe returnTo URLs", async () => {
      const authClient = await createAuthClient({
        signInReturnToPath: "/safe-path"
      });
      const unsafeReturnTo = "https://malicious-site.com";

      // Mock the transactionStore.save method to verify the saved state
      const originalSave = authClient["transactionStore"].save;
      authClient["transactionStore"].save = vi.fn(
        async (cookies, state, reqCookies) => {
          // Should use the default safe path instead of the malicious one
          expect(state.returnTo).toBe("/safe-path");
          return originalSave.call(
            authClient["transactionStore"],
            cookies,
            state,
            reqCookies
          );
        }
      );

      await authClient.startInteractiveLogin({ returnTo: unsafeReturnTo });

      expect(authClient["transactionStore"].save).toHaveBeenCalled();
    });

    it("should pass authorization parameters to the authorization URL", async () => {
      const authClient = await createAuthClient();
      const authorizationParameters = {
        audience: "https://api.example.com",
        scope: "openid profile email custom_scope"
      };

      // Spy on the authorizationUrl method to verify the passed params
      const originalAuthorizationUrl = authClient["authorizationUrl"];
      authClient["authorizationUrl"] = vi.fn(async (params) => {
        // Verify the audience is set correctly
        expect(params.get("audience")).toBe(authorizationParameters.audience);
        // Verify the scope is set correctly
        expect(params.get("scope")).toBe(authorizationParameters.scope);
        return originalAuthorizationUrl.call(authClient, params);
      });

      await authClient.startInteractiveLogin({ authorizationParameters });

      expect(authClient["authorizationUrl"]).toHaveBeenCalled();
    });

    it("should throw when appBaseUrl is missing and no request is available", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      await expect(authClient.startInteractiveLogin()).rejects.toThrow(
        InvalidConfigurationError
      );
    });

    it("should throw when request host cannot be inferred", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const request = {
        headers: new Headers(),
        nextUrl: {
          host: "",
          protocol: ""
        }
      } as unknown as NextRequest;

      await expect(
        authClient.startInteractiveLogin({}, request)
      ).rejects.toThrow(InvalidConfigurationError);
    });

    it("should handle pushed authorization requests (PAR) correctly", async () => {
      let parRequestCalled = false;
      const mockFetch = getMockAuthorizationServer({
        onParRequest: async () => {
          parRequestCalled = true;
        }
      });

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        pushedAuthorizationRequests: true,
        authorizationParameters: {
          scope: "openid profile email"
        },
        fetch: mockFetch
      });

      await authClient.startInteractiveLogin();

      // Verify that PAR was used
      expect(parRequestCalled).toBe(true);
    });

    it("should save the transaction state with correct values", async () => {
      const authClient = await createAuthClient();
      const returnTo = "/custom-path";

      // Instead of mocking the oauth functions, we'll just check the structure of the transaction state
      const originalSave = authClient["transactionStore"].save;
      authClient["transactionStore"].save = vi.fn(
        async (cookies, transactionState) => {
          expect(transactionState).toEqual(
            expect.objectContaining({
              nonce: expect.any(String),
              codeVerifier: expect.any(String),
              responseType: RESPONSE_TYPES.CODE,
              state: expect.any(String),
              returnTo: "/custom-path"
            })
          );
          return originalSave.call(
            authClient["transactionStore"],
            cookies,
            transactionState
          );
        }
      );

      await authClient.startInteractiveLogin({ returnTo });

      expect(authClient["transactionStore"].save).toHaveBeenCalled();
    });

    it("should merge configuration authorizationParameters with method arguments", async () => {
      const configScope = "openid profile email";
      const configAudience = "https://default-api.example.com";
      const authClient = await createAuthClient({
        authorizationParameters: {
          scope: configScope,
          audience: configAudience
        }
      });

      const methodScope = "openid profile email custom_scope";
      const methodAudience = "https://custom-api.example.com";

      // Spy on the authorizationUrl method to verify the passed params
      const originalAuthorizationUrl = authClient["authorizationUrl"];
      authClient["authorizationUrl"] = vi.fn(async (params) => {
        // Method's authorization parameters should override config
        expect(params.get("audience")).toBe(methodAudience);
        expect(params.get("scope")).toBe(methodScope);
        return originalAuthorizationUrl.call(authClient, params);
      });

      await authClient.startInteractiveLogin({
        authorizationParameters: {
          scope: methodScope,
          audience: methodAudience
        }
      });

      expect(authClient["authorizationUrl"]).toHaveBeenCalled();
    });

    // Add tests for handleLogin method
    it("should create correct options in handleLogin with returnTo parameter excluded", async () => {
      const authClient = await createAuthClient();

      // Mock startInteractiveLogin to check what options are passed to it
      const originalStartInteractiveLogin = authClient.startInteractiveLogin;
      authClient.startInteractiveLogin = vi.fn(async (options, req) => {
        expect(options).toEqual({
          authorizationParameters: { foo: "bar" },
          returnTo: "custom-return"
        });
        return originalStartInteractiveLogin.call(authClient, options, req);
      });

      const reqUrl = new URL(
        "https://example.com/auth/login?foo=bar&returnTo=custom-return"
      );
      const req = new NextRequest(reqUrl, { method: "GET" });

      await authClient.handleLogin(req);

      expect(authClient.startInteractiveLogin).toHaveBeenCalled();
    });

    it("should handle PAR correctly in handleLogin by forwarding all params except returnTo", async () => {
      const authClient = await createAuthClient({
        pushedAuthorizationRequests: true
      });

      // Mock startInteractiveLogin to check what options are passed to it
      const originalStartInteractiveLogin = authClient.startInteractiveLogin;
      authClient.startInteractiveLogin = vi.fn(async (options, req) => {
        expect(options).toEqual({
          authorizationParameters: {
            foo: "bar"
          },
          returnTo: "custom-return"
        });
        return originalStartInteractiveLogin.call(authClient, options, req);
      });

      const reqUrl = new URL(
        "https://example.com/auth/login?foo=bar&returnTo=custom-return"
      );
      const req = new NextRequest(reqUrl, { method: "GET" });

      await authClient.handleLogin(req);

      expect(authClient.startInteractiveLogin).toHaveBeenCalled();
    });
  });

  describe("getConnectionTokenSet", async () => {
    it("should call for an access token when no connection token set in the session", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const fetchSpy = getMockAuthorizationServer({
        tokenEndpointResponse: {
          token_type: "Bearer",
          access_token: DEFAULT.accessToken,
          expires_in: 86400 // expires in 10 days
        } as oauth.TokenEndpointResponse
      });

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: fetchSpy
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt
      };

      const response = await authClient.getConnectionTokenSet(
        tokenSet,
        undefined,
        { connection: "google-oauth2", login_hint: "000100123" }
      );
      const [error, connectionTokenSet] = response;
      expect(error).toBe(null);
      expect(fetchSpy).toHaveBeenCalled();
      expect(connectionTokenSet).toEqual({
        accessToken: DEFAULT.accessToken,
        connection: "google-oauth2",
        expiresAt: expect.any(Number)
      });
    });

    it("should return access token from the session when connection token set in the session is not expired", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const fetchSpy = vi.fn();
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: fetchSpy
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt
      };

      const response = await authClient.getConnectionTokenSet(
        tokenSet,
        {
          connection: "google-oauth2",
          accessToken: "fc_at",
          expiresAt: Math.floor(Date.now() / 1000) + 86400
        },
        { connection: "google-oauth2", login_hint: "000100123" }
      );
      const [error, connectionTokenSet] = response;
      expect(error).toBe(null);
      expect(connectionTokenSet).toEqual({
        accessToken: "fc_at",
        connection: "google-oauth2",
        expiresAt: expect.any(Number)
      });
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("should call for an access token when connection token set in the session is expired", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const fetchSpy = getMockAuthorizationServer({
        tokenEndpointResponse: {
          token_type: "Bearer",
          access_token: DEFAULT.accessToken,
          expires_in: 86400 // expires in 10 days
        } as oauth.TokenEndpointResponse
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: fetchSpy
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt
      };

      const response = await authClient.getConnectionTokenSet(
        tokenSet,
        { connection: "google-oauth2", accessToken: "fc_at", expiresAt },
        { connection: "google-oauth2", login_hint: "000100123" }
      );
      const [error, connectionTokenSet] = response;
      expect(error).toBe(null);
      expect(connectionTokenSet).toEqual({
        accessToken: DEFAULT.accessToken,
        connection: "google-oauth2",
        expiresAt: expect.any(Number)
      });
      expect(fetchSpy).toHaveBeenCalled();
    });

    it("should return an error if the discovery endpoint could not be fetched", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          discoveryResponse: new Response(null, { status: 500 })
        })
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt
      };

      const [error, connectionTokenSet] =
        await authClient.getConnectionTokenSet(tokenSet, undefined, {
          connection: "google-oauth2"
        });
      expect(error?.code).toEqual("discovery_error");
      expect(connectionTokenSet).toBeNull();
    });

    it("should return an error if the token set does not contain a refresh token", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        expiresAt
      };

      const [error, connectionTokenSet] =
        await authClient.getConnectionTokenSet(tokenSet, undefined, {
          connection: "google-oauth2"
        });
      expect(error?.code).toEqual("missing_refresh_token");
      expect(connectionTokenSet).toBeNull();
    });

    it("should return an error and capture it as the cause when exchange failed", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointErrorResponse: {
            error: "some-error-code",
            error_description: "some-error-description"
          }
        })
      });

      const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
      const tokenSet = {
        accessToken: DEFAULT.accessToken,
        refreshToken: DEFAULT.refreshToken,
        expiresAt
      };

      const [error, connectionTokenSet] =
        await authClient.getConnectionTokenSet(tokenSet, undefined, {
          connection: "google-oauth2"
        });
      expect(error?.code).toEqual("failed_to_exchange_refresh_token");
      expect(error?.cause?.code).toEqual("some-error-code");
      expect(error?.cause?.message).toEqual("some-error-description");
      expect(connectionTokenSet).toBeNull();
    });

    it("should use access token as subject token when subject_token_type is SUBJECT_TYPE_ACCESS_TOKEN", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });

      let capturedRequestBody: any = null;
      const mockFetch = vi.fn(
        async (
          input: RequestInfo | URL,
          init?: RequestInit
        ): Promise<Response> => {
          const url = new URL(input instanceof Request ? input.url : input);

          if (url.pathname === "/oauth/token") {
            // Capture the request body for validation
            if (init?.body) {
              capturedRequestBody = init.body;
            }

            return Response.json({
              access_token: "federated-access-token",
              token_type: "Bearer",
              expires_in: 3600
            });
          }

          // discovery URL
          if (url.pathname === "/.well-known/openid-configuration") {
            return Response.json(_authorizationServerMetadata);
          }

          return new Response("Not found", { status: 404 });
        }
      );

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: mockFetch
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 3600;
      const tokenSet = {
        accessToken: "existing-access-token",
        refreshToken: "existing-refresh-token",
        expiresAt
      };

      const [error, connectionTokenSet] =
        await authClient.getConnectionTokenSet(tokenSet, undefined, {
          connection: "google-oauth2",
          subject_token_type: SUBJECT_TOKEN_TYPES.SUBJECT_TYPE_ACCESS_TOKEN
        });

      expect(error).toBeNull();
      expect(connectionTokenSet).toEqual({
        accessToken: "federated-access-token",
        connection: "google-oauth2",
        expiresAt: expect.any(Number)
      });

      // Verify the request was made with correct parameters
      expect(capturedRequestBody).toBeTruthy();
      const urlParams = new URLSearchParams(capturedRequestBody);
      expect(urlParams.get("subject_token_type")).toBe(
        "urn:ietf:params:oauth:token-type:access_token"
      );
      expect(urlParams.get("subject_token")).toBe("existing-access-token");
      expect(urlParams.get("grant_type")).toBe(
        "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"
      );
      expect(urlParams.get("connection")).toBe("google-oauth2");
    });

    it("should use refresh token as subject token when subject_token_type is SUBJECT_TYPE_REFRESH_TOKEN", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });

      let capturedRequestBody: any = null;
      const mockFetch = vi.fn(
        async (
          input: RequestInfo | URL,
          init?: RequestInit
        ): Promise<Response> => {
          const url = new URL(input instanceof Request ? input.url : input);

          if (url.pathname === "/oauth/token") {
            // Capture the request body for validation
            if (init?.body) {
              capturedRequestBody = init.body;
            }

            return Response.json({
              access_token: "federated-access-token",
              token_type: "Bearer",
              expires_in: 3600
            });
          }

          // discovery URL
          if (url.pathname === "/.well-known/openid-configuration") {
            return Response.json(_authorizationServerMetadata);
          }

          return new Response("Not found", { status: 404 });
        }
      );

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: mockFetch
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 3600;
      const tokenSet = {
        accessToken: "existing-access-token",
        refreshToken: "existing-refresh-token",
        expiresAt
      };

      const [error, connectionTokenSet] =
        await authClient.getConnectionTokenSet(tokenSet, undefined, {
          connection: "google-oauth2",
          subject_token_type: SUBJECT_TOKEN_TYPES.SUBJECT_TYPE_REFRESH_TOKEN
        });

      expect(error).toBeNull();
      expect(connectionTokenSet).toEqual({
        accessToken: "federated-access-token",
        connection: "google-oauth2",
        expiresAt: expect.any(Number)
      });

      // Verify the request was made with correct parameters
      expect(capturedRequestBody).toBeTruthy();
      const urlParams = new URLSearchParams(capturedRequestBody);
      expect(urlParams.get("subject_token_type")).toBe(
        "urn:ietf:params:oauth:token-type:refresh_token"
      );
      expect(urlParams.get("subject_token")).toBe("existing-refresh-token");
      expect(urlParams.get("grant_type")).toBe(
        "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"
      );
      expect(urlParams.get("connection")).toBe("google-oauth2");
    });

    it("should default to refresh token when no subject_token_type is specified", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });

      let capturedRequestBody: any = null;
      const mockFetch = vi.fn(
        async (
          input: RequestInfo | URL,
          init?: RequestInit
        ): Promise<Response> => {
          const url = new URL(input instanceof Request ? input.url : input);

          if (url.pathname === "/oauth/token") {
            // Capture the request body for validation
            if (init?.body) {
              capturedRequestBody = init.body;
            }

            return Response.json({
              access_token: "federated-access-token",
              token_type: "Bearer",
              expires_in: 3600
            });
          }

          // discovery URL
          if (url.pathname === "/.well-known/openid-configuration") {
            return Response.json(_authorizationServerMetadata);
          }

          return new Response("Not found", { status: 404 });
        }
      );

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: mockFetch
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 3600;
      const tokenSet = {
        accessToken: "existing-access-token",
        refreshToken: "existing-refresh-token",
        expiresAt
      };

      const [error, connectionTokenSet] =
        await authClient.getConnectionTokenSet(tokenSet, undefined, {
          connection: "google-oauth2"
          // No subject_token_type specified - should default to refresh token
        });

      expect(error).toBeNull();
      expect(connectionTokenSet).toEqual({
        accessToken: "federated-access-token",
        connection: "google-oauth2",
        expiresAt: expect.any(Number)
      });

      // Verify the request defaults to refresh token parameters
      expect(capturedRequestBody).toBeTruthy();
      const urlParams = new URLSearchParams(capturedRequestBody);
      expect(urlParams.get("subject_token_type")).toBe(
        "urn:ietf:params:oauth:token-type:refresh_token"
      );
      expect(urlParams.get("subject_token")).toBe("existing-refresh-token");
      expect(urlParams.get("grant_type")).toBe(
        "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"
      );
      expect(urlParams.get("connection")).toBe("google-oauth2");
    });

    it("should return error when access token is requested but not available", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });

      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointErrorResponse: {
            error: "invalid_request",
            error_description:
              "The request is missing a required parameter or is otherwise malformed."
          }
        })
      });

      const expiresAt = Math.floor(Date.now() / 1000) + 3600;
      const tokenSet = {
        // Empty access token means unavailable
        accessToken: "",
        refreshToken: "existing-refresh-token",
        expiresAt
      };

      const [error, connectionTokenSet] =
        await authClient.getConnectionTokenSet(tokenSet, undefined, {
          connection: "google-oauth2",
          subject_token_type: SUBJECT_TOKEN_TYPES.SUBJECT_TYPE_ACCESS_TOKEN
        });

      // Should get an error when trying to use an empty access token
      expect(error).toBeTruthy();
      expect(error?.code).toBe("failed_to_exchange_refresh_token");
      expect(connectionTokenSet).toBeNull();
    });
  });

  describe("backchannelAuthentication", async () => {
    it("should return an error if backchannel authentication is not enabled", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          discoveryResponse: Response.json(
            {
              ..._authorizationServerMetadata,
              backchannel_authentication_endpoint: null,
              backchannel_token_delivery_modes_supported: null
            },
            {
              status: 200,
              headers: {
                "content-type": "application/json"
              }
            }
          )
        })
      });

      const [error, _] = await authClient.backchannelAuthentication({
        bindingMessage: "test-message",
        loginHint: {
          sub: DEFAULT.sub
        }
      });
      expect(error?.code).toEqual(
        "backchannel_authentication_not_supported_error"
      );
    });

    it("should return the token set when successfully authenticated", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer()
      });

      const [error, res] = await authClient.backchannelAuthentication({
        bindingMessage: "test-message",
        loginHint: {
          sub: DEFAULT.sub
        }
      });
      expect(error).toBeNull();
      expect(res).toEqual({
        idTokenClaims: {
          aud: DEFAULT.clientId,
          auth_time: expect.any(Number),
          exp: expect.any(Number),
          "https://example.com/custom_claim": "value",
          iat: expect.any(Number),
          iss: `https://${DEFAULT.domain}/`,
          nonce: expect.any(String),
          sid: DEFAULT.sid,
          sub: DEFAULT.sub
        },
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          expiresAt: expect.any(Number),
          idToken: expect.any(String),
          refreshToken: DEFAULT.refreshToken
        }
      });
    });

    it("should return an error when the user rejects the authorization request", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),

        fetch: getMockAuthorizationServer({
          tokenEndpointErrorResponse: {
            error: "access_denied",
            error_description:
              "The end-user denied the authorization request or it has been expired"
          }
        })
      });

      const [error, res] = await authClient.backchannelAuthentication({
        bindingMessage: "test-message",
        loginHint: {
          sub: DEFAULT.sub
        }
      });
      expect((error as BackchannelAuthenticationError)?.cause?.code).toEqual(
        "access_denied"
      );
      expect(res).toBeNull();
    });

    it("should forward any statically configured authorization parameters", async () => {
      const customScope = "openid profile email offline_access custom_scope";
      const customAudience = "urn:mystore:api";
      const customParamValue = "custom_value";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        authorizationParameters: {
          scope: customScope,
          audience: customAudience,
          custom_param: customParamValue
        },
        fetch: getMockAuthorizationServer({
          onBackchannelAuthRequest: async (req) => {
            const formBody = await req.formData();
            expect(formBody.get("scope")).toEqual(customScope);
            expect(formBody.get("audience")).toEqual(customAudience);
            expect(formBody.get("custom_param")).toEqual(customParamValue);
          }
        })
      });

      const [error, _] = await authClient.backchannelAuthentication({
        bindingMessage: "test-message",
        loginHint: {
          sub: DEFAULT.sub
        }
      });

      expect(error).toBeNull();
    });

    it("should forward any dynamically specified authorization parameters", async () => {
      const customScope = "openid profile email offline_access custom_scope";
      const customAudience = "urn:mystore:api";
      const customParamValue = "custom_value";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        fetch: getMockAuthorizationServer({
          onBackchannelAuthRequest: async (req) => {
            const formBody = await req.formData();
            expect(formBody.get("scope")).toEqual(customScope);
            expect(formBody.get("audience")).toEqual(customAudience);
            expect(formBody.get("custom_param")).toEqual(customParamValue);
          }
        })
      });

      const [error, _] = await authClient.backchannelAuthentication({
        bindingMessage: "test-message",
        loginHint: {
          sub: DEFAULT.sub
        },
        authorizationParams: {
          scope: customScope,
          audience: customAudience,
          custom_param: customParamValue
        }
      });

      expect(error).toBeNull();
    });

    it("should forward scope when scope defined as a map for the default audience", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        authorizationParameters: {
          audience: "default-audience",
          scope: {
            "default-audience": "openid default-scope"
          }
        },

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        fetch: getMockAuthorizationServer({
          onBackchannelAuthRequest: async (req) => {
            const formBody = await req.formData();
            expect(formBody.get("scope")).toEqual("openid default-scope");
          }
        })
      });

      const [error, _] = await authClient.backchannelAuthentication({
        bindingMessage: "test-message",
        loginHint: {
          sub: DEFAULT.sub
        }
      });

      expect(error).toBeNull();
    });

    it("should forward DEFAULT_SCOPES when no scope defined", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        fetch: getMockAuthorizationServer({
          onBackchannelAuthRequest: async (req) => {
            const formBody = await req.formData();
            expect(formBody.get("scope")).toEqual(DEFAULT_SCOPES);
          }
        })
      });

      // Unset the scope
      // This is not a real scenario, as scope is always defined on the authorization parameters
      // because of the defaulting in the constructor and merge function.
      (authClient as any).authorizationParameters.scope = undefined;

      const [error, _] = await authClient.backchannelAuthentication({
        bindingMessage: "test-message",
        loginHint: {
          sub: DEFAULT.sub
        }
      });

      expect(error).toBeNull();
    });

    it("should forward DEFAULT_SCOPES when scope defined as a map with no entry for the audience", async () => {
      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        authorizationParameters: {
          audience: "default-audience",
          scope: {
            "default-audience": "openid default-scope"
          }
        },

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        fetch: getMockAuthorizationServer({
          onBackchannelAuthRequest: async (req) => {
            const formBody = await req.formData();
            expect(formBody.get("scope")).toEqual(DEFAULT_SCOPES);
          }
        })
      });

      const [error, _] = await authClient.backchannelAuthentication({
        bindingMessage: "test-message",
        loginHint: {
          sub: DEFAULT.sub
        },
        authorizationParams: {
          audience: "some-other-audience"
        }
      });

      expect(error).toBeNull();
    });

    it("should give precedence to dynamically provided authorization parameters over statically configured ones", async () => {
      const customScope = "openid profile email offline_access custom_scope";
      const customParamValue = "custom_value";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({
        secret
      });
      const sessionStore = new StatelessSessionStore({
        secret
      });
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,

        secret,
        appBaseUrl: DEFAULT.appBaseUrl,

        routes: getDefaultRoutes(),
        authorizationParameters: {
          scope: customScope,
          audience: "static-config-aud",
          custom_param: customParamValue
        },
        fetch: getMockAuthorizationServer({
          onBackchannelAuthRequest: async (req) => {
            const formBody = await req.formData();
            expect(formBody.get("scope")).toEqual(customScope);
            expect(formBody.get("audience")).toEqual(
              "dynamically-specific-aud"
            );
            expect(formBody.get("custom_param")).toEqual(customParamValue);
          }
        })
      });

      const [error, _] = await authClient.backchannelAuthentication({
        bindingMessage: "test-message",
        loginHint: {
          sub: DEFAULT.sub
        },
        authorizationParams: {
          scope: customScope,
          audience: "dynamically-specific-aud",
          custom_param: customParamValue
        }
      });

      expect(error).toBeNull();
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
