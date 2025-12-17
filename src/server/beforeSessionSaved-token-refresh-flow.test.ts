import { NextRequest } from "next/server.js";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import * as oauth from "oauth4webapi";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { SessionData } from "../types/index.js";
import { AuthClient } from "./auth-client.js";
import { decrypt, encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";
import { Auth0NextRequest } from "./abstraction/auth0-next-request.js";

/**
 * Test suite for the beforeSessionSaved hook.
 */

// Test constants
const domain = "guabu.us.auth0.com";
const clientId = "client_123";
const clientSecret = "client-secret";
const appBaseUrl = "https://example.com";
const accessToken = "at_123";
const refreshToken = "rt_123";
const sub = "user_123";
const sid = "auth0-sid";
const alg = "RS256";

// Generate key pair for token signing
let keyPair: jose.GenerateKeyPairResult;

// OIDC Discovery metadata
const discoveryMetadata = {
  issuer: `https://${domain}/`,
  authorization_endpoint: `https://${domain}/authorize`,
  token_endpoint: `https://${domain}/oauth/token`,
  userinfo_endpoint: `https://${domain}/userinfo`,
  jwks_uri: `https://${domain}/.well-known/jwks.json`,
  end_session_endpoint: `https://${domain}/oidc/logout`
};

/**
 * MSW handlers for OAuth2 endpoints.
 * These are declarative and can be customized per test using server.use()
 */
const handlers = [
  // OIDC Discovery Endpoint
  http.get(`https://${domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(discoveryMetadata);
  }),

  // JWKS Endpoint
  http.get(`https://${domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({ keys: [jwk] });
  }),

  // Token Exchange Endpoint
  http.post(
    `https://${domain}/oauth/token`,
    async ({ request }: { request: Request }) => {
      const body = await request.formData();
      const grantType = body.get("grant_type");

      // Authorization code grant (login flow)
      if (grantType === "authorization_code") {
        const idTokenJwt = await new jose.SignJWT({
          sub,
          sid,
          nonce: "nonce-value",
          auth_time: Math.floor(Date.now() / 1000),
          iss: discoveryMetadata.issuer,
          aud: clientId
        })
          .setProtectedHeader({ alg })
          .setIssuedAt()
          .setExpirationTime("1h")
          .sign(keyPair.privateKey);

        return HttpResponse.json({
          access_token: accessToken,
          refresh_token: refreshToken,
          id_token: idTokenJwt,
          token_type: "Bearer",
          expires_in: 86400
        } as oauth.TokenEndpointResponse);
      }

      // Refresh token grant (token refresh)
      if (grantType === "refresh_token") {
        const newAccessToken = "at_new_refreshed";
        const idTokenJwt = await new jose.SignJWT({
          sub,
          sid,
          auth_time: Math.floor(Date.now() / 1000),
          iss: discoveryMetadata.issuer,
          aud: clientId
        })
          .setProtectedHeader({ alg })
          .setIssuedAt()
          .setExpirationTime("1h")
          .sign(keyPair.privateKey);

        return HttpResponse.json({
          access_token: newAccessToken,
          refresh_token: refreshToken,
          id_token: idTokenJwt,
          token_type: "Bearer",
          expires_in: 86400
        } as oauth.TokenEndpointResponse);
      }

      // Unknown grant type
      return HttpResponse.json(
        { error: "unsupported_grant_type" } as oauth.OAuth2Error,
        { status: 400 }
      );
    }
  )
];

// Setup MSW server for all tests in this suite
const server = setupServer(...handlers);

describe("AuthClient - beforeSessionSaved hook", async () => {
  beforeAll(async () => {
    // Initialize key pair and start MSW server
    keyPair = await jose.generateKeyPair(alg);
    server.listen();
  });

  afterEach(() => {
    // Reset any custom handlers added in individual tests
    server.resetHandlers();
  });

  afterAll(() => {
    // Clean up MSW server
    server.close();
  });

  it("should call beforeSessionSaved with updated tokens after token refresh (handleAccessToken)", async () => {
    const currentAccessToken = "at_old";
    const newAccessToken = "at_new_refreshed";

    const secret = await generateSecret(32);
    const transactionStore = new TransactionStore({
      secret
    });
    const sessionStore = new StatelessSessionStore({
      secret
    });

    // Track what the hook receives
    let hookReceivedAccessToken: string | undefined;
    let hookReceivedSession: SessionData | undefined;

    const authClient = new AuthClient({
      transactionStore,
      sessionStore,

      domain: domain,
      clientId: clientId,
      clientSecret: clientSecret,

      secret,
      appBaseUrl: appBaseUrl,

      routes: getDefaultRoutes(),

      beforeSessionSaved: async (session) => {
        // Capture what the hook receives
        hookReceivedAccessToken = session.tokenSet?.accessToken;
        hookReceivedSession = session;

        // Hook can modify the session
        return {
          ...session,
          user: {
            ...session.user,
            enriched: true
          }
        };
      }
    });

    // Create an expired session that needs token refresh
    const expiresAt = Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60; // expired 10 days ago
    const originalSession: SessionData = {
      user: {
        sub: sub,
        name: "John Doe",
        email: "john@example.com",
        picture: "https://example.com/john.jpg"
      },
      tokenSet: {
        accessToken: currentAccessToken,
        scope: "openid profile email",
        refreshToken: refreshToken,
        expiresAt
      },
      internal: {
        sid: sid,
        createdAt: Math.floor(Date.now() / 1000)
      }
    };

    const maxAge = 60 * 60; // 1 hour
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const sessionCookie = await encrypt(originalSession, secret, expiration);
    const headers = new Headers();
    headers.append("cookie", `__session=${sessionCookie}`);
    const request = new NextRequest(new URL("/auth/access-token", appBaseUrl), {
      method: "GET",
      headers
    });

    const response = await authClient.handleAccessToken(new Auth0NextRequest(request));

    // Verify the response
    expect(response.status).toEqual(200);
    const responseBody = await response.json();
    expect(responseBody.token).toEqual(newAccessToken);

    // The hook should have received the UPDATED access token (not the old one)
    expect(hookReceivedAccessToken).toEqual(newAccessToken);
    expect(hookReceivedAccessToken).not.toEqual(currentAccessToken);

    // The hook should have received the complete updated session
    expect(hookReceivedSession?.tokenSet?.accessToken).toEqual(newAccessToken);
    expect(hookReceivedSession?.tokenSet?.refreshToken).toEqual(refreshToken);

    // Verify the session cookie is updated with hook modifications
    const updatedSessionCookie = response.cookies.get("__session");
    const { payload: updatedSession } = (await decrypt<SessionData>(
      updatedSessionCookie!.value,
      secret
    )) as jose.JWTDecryptResult<SessionData>;

    // Hook modifications should be persisted
    expect(updatedSession.user).toEqual(
      expect.objectContaining({
        enriched: true
      })
    );

    // Updated token should be in final session
    expect(updatedSession.tokenSet.accessToken).toEqual(newAccessToken);
  });
});
