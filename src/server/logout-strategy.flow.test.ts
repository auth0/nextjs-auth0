import { NextRequest, NextResponse } from "next/server.js";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it
} from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import type { SessionData } from "../types/index.js";
import { AuthClient } from "./auth-client.js";
import { encrypt } from "./cookies.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";
import { Auth0NextRequest, Auth0NextResponse } from "./http/index.js";

// Test constants
const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  sub: "test-user-id",
  sid: "test-session-id",
  idToken: "test-id-token",
  accessToken: "test-access-token",
  refreshToken: "test-refresh-token"
};

// Mock authorization server metadata
const authorizationServerMetadata = {
  issuer: `https://${DEFAULT.domain}/`,
  authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
  token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
  userinfo_endpoint: `https://${DEFAULT.domain}/userinfo`,
  jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
  end_session_endpoint: `https://${DEFAULT.domain}/oidc/logout`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: ["openid", "profile", "email"]
};

// MSW handlers
const handlers = [
  // OIDC Discovery Endpoint with end_session_endpoint
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(authorizationServerMetadata);
  })
];

const handlersWithoutEndSession = [
  // OIDC Discovery Endpoint without end_session_endpoint
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    const {
      end_session_endpoint: _end_session_endpoint,
      ...metadataWithoutEndSession
    } = authorizationServerMetadata;
    return HttpResponse.json(metadataWithoutEndSession);
  })
];

const server = setupServer(...handlers);

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

async function createSessionCookie(
  session: SessionData,
  secret: string
): Promise<string> {
  const maxAge = 60 * 60; // 1 hour
  const expiration = Math.floor(Date.now() / 1000 + maxAge);
  return await encrypt(session, secret, expiration);
}

describe("Logout Strategy Flow Tests", () => {
  let secret: string;
  let transactionStore: TransactionStore;
  let sessionStore: StatelessSessionStore;

  beforeEach(async () => {
    secret = await generateSecret(32);
    transactionStore = new TransactionStore({ secret });
    sessionStore = new StatelessSessionStore({ secret });
  });

  describe("logoutStrategy: 'auto' (default)", () => {
    it("should use OIDC logout when end_session_endpoint is available", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "auto",
        routes: getDefaultRoutes()
      });

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

      const sessionCookie = await createSessionCookie(session, secret);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.origin).toBe(`https://${DEFAULT.domain}`);
      expect(logoutUrl.pathname).toBe("/oidc/logout");
      expect(logoutUrl.searchParams.get("client_id")).toBe(DEFAULT.clientId);
      expect(logoutUrl.searchParams.get("post_logout_redirect_uri")).toBe(
        DEFAULT.appBaseUrl
      );
      expect(logoutUrl.searchParams.get("logout_hint")).toBe(DEFAULT.sid);
      expect(logoutUrl.searchParams.get("id_token_hint")).toBe(DEFAULT.idToken);
    });

    it("should fallback to v2 logout when end_session_endpoint is not available", async () => {
      // Switch to handlers without end_session_endpoint
      server.use(...handlersWithoutEndSession);

      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "auto",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.origin).toBe(`https://${DEFAULT.domain}`);
      expect(logoutUrl.pathname).toBe("/v2/logout");
      expect(logoutUrl.searchParams.get("client_id")).toBe(DEFAULT.clientId);
      expect(logoutUrl.searchParams.get("returnTo")).toBe(DEFAULT.appBaseUrl);
    });

    it("should handle returnTo parameter correctly with auto strategy", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "auto",
        routes: getDefaultRoutes()
      });

      const returnToUrl = "http://localhost:3000/custom-page";
      const url = new URL("/auth/logout", DEFAULT.appBaseUrl);
      url.searchParams.set("returnTo", returnToUrl);

      const request = new NextRequest(url, {
        method: "GET"
      });

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.searchParams.get("post_logout_redirect_uri")).toBe(
        returnToUrl
      );
    });
  });

  describe("logoutStrategy: 'oidc'", () => {
    it("should always use OIDC logout when strategy is set to 'oidc'", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "oidc",
        routes: getDefaultRoutes()
      });

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

      const sessionCookie = await createSessionCookie(session, secret);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/oidc/logout");
    });

    it("should fail gracefully when OIDC endpoint is not available but strategy is 'oidc'", async () => {
      // Switch to handlers without end_session_endpoint
      server.use(...handlersWithoutEndSession);

      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "oidc",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(500);
      expect(await response.text()).toBe(
        "OIDC RP-Initiated Logout is not supported by the authorization server. Enable it or use a different logout strategy."
      );
    });
  });

  describe("logoutStrategy: 'v2'", () => {
    it("should always use v2 logout when strategy is set to 'v2'", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "v2",
        routes: getDefaultRoutes()
      });

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

      const sessionCookie = await createSessionCookie(session, secret);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/v2/logout");
      expect(logoutUrl.searchParams.get("client_id")).toBe(DEFAULT.clientId);
      expect(logoutUrl.searchParams.get("returnTo")).toBe(DEFAULT.appBaseUrl);
    });

    it("should handle wildcard URLs correctly with v2 strategy", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "v2",
        routes: getDefaultRoutes()
      });

      const wildcardUrl = "http://localhost:3000/*/about";
      const url = new URL("/auth/logout", DEFAULT.appBaseUrl);
      url.searchParams.set("returnTo", wildcardUrl);

      const request = new NextRequest(url, {
        method: "GET"
      });

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/v2/logout");
      expect(logoutUrl.searchParams.get("returnTo")).toBe(wildcardUrl);
    });

    it("should use v2 logout even when OIDC endpoint is available", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "v2",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/v2/logout");
    });
  });

  describe("Session Management", () => {
    it("should properly clean up sessions and cookies for all strategies", async () => {
      const strategies: Array<"auto" | "oidc" | "v2"> = ["auto", "oidc", "v2"];

      for (const strategy of strategies) {
        const authClient = new AuthClient({
          domain: DEFAULT.domain,
          clientId: DEFAULT.clientId,
          clientSecret: DEFAULT.clientSecret,
          appBaseUrl: DEFAULT.appBaseUrl,
          secret,
          transactionStore,
          sessionStore,
          logoutStrategy: strategy,
          routes: getDefaultRoutes()
        });

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

        const sessionCookie = await createSessionCookie(session, secret);
        const headers = new Headers();
        headers.append("cookie", `__session=${sessionCookie}`);

        const request = new NextRequest(
          new URL("/auth/logout", DEFAULT.appBaseUrl),
          {
            method: "GET",
            headers
          }
        );

        const auth0Req = new Auth0NextRequest(request);
        const auth0Res = new Auth0NextResponse(NextResponse.next());
        await authClient.handleLogout(auth0Req, auth0Res);
        const response = auth0Res.res;

        // All strategies should redirect (except oidc without endpoint, but we're testing with endpoint)
        expect(response.status).toBe(307);

        // Session cookie should be cleared
        const cookie = response.cookies.get("__session");
        expect(cookie?.value).toBe("");
        expect(cookie?.maxAge).toBe(0);

        // Response should have cache control headers
        expect(response.headers.get("cache-control")).toContain("no-cache");
      }
    });

    it("should handle logout without existing session", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "auto",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/oidc/logout");
      // Without session, these parameters should not be present
      expect(logoutUrl.searchParams.get("logout_hint")).toBeNull();
      expect(logoutUrl.searchParams.get("id_token_hint")).toBeNull();
    });
  });

  describe("includeIdTokenHintInOIDCLogoutUrl option with different logout strategies", () => {
    it("should exclude id_token_hint from OIDC logout URL when includeIdTokenHintInOIDCLogoutUrl is false with auto strategy", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "auto",
        includeIdTokenHintInOIDCLogoutUrl: false,
        routes: getDefaultRoutes()
      });

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

      const sessionCookie = await createSessionCookie(session, secret);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/oidc/logout");
      expect(logoutUrl.searchParams.get("logout_hint")).toBe(DEFAULT.sid);
      expect(logoutUrl.searchParams.get("id_token_hint")).toBeNull();
    });

    it("should exclude id_token_hint from OIDC logout URL when includeIdTokenHintInOIDCLogoutUrl is false with oidc strategy", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "oidc",
        includeIdTokenHintInOIDCLogoutUrl: false,
        routes: getDefaultRoutes()
      });

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

      const sessionCookie = await createSessionCookie(session, secret);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/oidc/logout");
      expect(logoutUrl.searchParams.get("logout_hint")).toBe(DEFAULT.sid);
      expect(logoutUrl.searchParams.get("id_token_hint")).toBeNull();
    });

    it("should not affect v2 logout strategy (includeIdTokenHintInOIDCLogoutUrl option has no effect)", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "v2",
        includeIdTokenHintInOIDCLogoutUrl: false, // should have no effect on v2 logout
        routes: getDefaultRoutes()
      });

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

      const sessionCookie = await createSessionCookie(session, secret);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/v2/logout");
      // v2 logout doesn't use these parameters anyway
      expect(logoutUrl.searchParams.get("logout_hint")).toBeNull();
      expect(logoutUrl.searchParams.get("id_token_hint")).toBeNull();
    });
  });

  describe("Federated logout support", () => {
    it("should add federated parameter to OIDC logout URL when federated is present in query", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "oidc",
        routes: getDefaultRoutes()
      });

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

      const sessionCookie = await createSessionCookie(session, secret);
      const headers = new Headers();
      headers.append("cookie", `__session=${sessionCookie}`);

      const request = new NextRequest(
        new URL("/auth/logout?federated", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.origin).toBe(`https://${DEFAULT.domain}`);
      expect(logoutUrl.pathname).toBe("/oidc/logout");
      expect(logoutUrl.searchParams.get("client_id")).toBe(DEFAULT.clientId);
      expect(logoutUrl.searchParams.get("post_logout_redirect_uri")).toBe(
        DEFAULT.appBaseUrl
      );
      expect(logoutUrl.searchParams.get("logout_hint")).toBe(DEFAULT.sid);
      expect(logoutUrl.searchParams.get("id_token_hint")).toBe(DEFAULT.idToken);
      expect(logoutUrl.searchParams.has("federated")).toBe(true);
      expect(logoutUrl.searchParams.get("federated")).toBe("");
    });

    it("should add federated parameter to v2 logout URL when federated is present in query", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "v2",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL("/auth/logout?federated", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.origin).toBe(`https://${DEFAULT.domain}`);
      expect(logoutUrl.pathname).toBe("/v2/logout");
      expect(logoutUrl.searchParams.get("client_id")).toBe(DEFAULT.clientId);
      expect(logoutUrl.searchParams.get("returnTo")).toBe(DEFAULT.appBaseUrl);
      expect(logoutUrl.searchParams.has("federated")).toBe(true);
      expect(logoutUrl.searchParams.get("federated")).toBe("");
    });

    it("should work with federated parameter and custom returnTo", async () => {
      const customReturnTo = "https://example.com/custom-logout";
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "v2",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL(
          `/auth/logout?federated&returnTo=${encodeURIComponent(customReturnTo)}`,
          DEFAULT.appBaseUrl
        ),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.searchParams.get("returnTo")).toBe(customReturnTo);
      expect(logoutUrl.searchParams.has("federated")).toBe(true);
    });

    it("should work with auto strategy and federated parameter when OIDC is available", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "auto",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL("/auth/logout?federated", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/oidc/logout");
      expect(logoutUrl.searchParams.has("federated")).toBe(true);
    });

    it("should work with auto strategy and federated parameter when OIDC is not available", async () => {
      // Switch to handlers without end_session_endpoint
      server.use(...handlersWithoutEndSession);

      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "auto",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL("/auth/logout?federated", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.pathname).toBe("/v2/logout");
      expect(logoutUrl.searchParams.has("federated")).toBe(true);
    });

    it("should not add federated parameter when not present in query", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "v2",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL("/auth/logout", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.searchParams.has("federated")).toBe(false);
    });

    it("should handle federated parameter with value (federated=true)", async () => {
      const authClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret,
        transactionStore,
        sessionStore,
        logoutStrategy: "v2",
        routes: getDefaultRoutes()
      });

      const request = new NextRequest(
        new URL("/auth/logout?federated=true", DEFAULT.appBaseUrl),
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClient.handleLogout(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("Location");
      expect(location).toBeTruthy();

      const logoutUrl = new URL(location!);
      expect(logoutUrl.searchParams.has("federated")).toBe(true);
      expect(logoutUrl.searchParams.get("federated")).toBe("");
    });
  });
});
