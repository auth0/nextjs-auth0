import { NextRequest, NextResponse } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  Auth0NextRequest,
  Auth0NextResponse
} from "../src/server/http/index.js";
import { AuthClient } from "../src/server/auth-client.js";
import { StatelessSessionStore } from "../src/server/session/stateless-session-store.js";
import { TransactionStore } from "../src/server/transaction-store.js";
import { getDefaultRoutes } from "../src/test/defaults.js";

const DEFAULT = {
  domain: "test.auth0.com",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "https://example.com",
  secret: "super-secret-32-character-string"
};

function getMockAuthorizationServer(options: { supportPAR?: boolean } = {}) {
  const { supportPAR = true } = options;

  return vi
    .fn()
    .mockImplementation(
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

        // Discovery endpoint
        if (url.pathname === "/.well-known/openid-configuration") {
          const metadata = {
            issuer: `https://${DEFAULT.domain}`,
            authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
            token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
            userinfo_endpoint: `https://${DEFAULT.domain}/userinfo`,
            end_session_endpoint: `https://${DEFAULT.domain}/v2/logout`,
            jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
            response_types_supported: ["code"],
            code_challenge_methods_supported: ["S256"],
            scopes_supported: ["openid", "profile", "email"]
          };

          if (supportPAR) {
            (metadata as any).pushed_authorization_request_endpoint =
              `https://${DEFAULT.domain}/oauth/par`;
          }

          return new Response(JSON.stringify(metadata), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }

        // PAR endpoint
        if (url.pathname === "/oauth/par" && supportPAR) {
          return new Response(
            JSON.stringify({
              request_uri: "urn:ietf:params:oauth:request_uri:test",
              expires_in: 30
            }),
            {
              status: 201,
              headers: { "Content-Type": "application/json" }
            }
          );
        }

        return new Response(null, { status: 404 });
      }
    );
}

describe("Organizations Feature", () => {
  let authClient: AuthClient;

  beforeEach(async () => {
    vi.clearAllMocks();
    vi.resetModules();

    const secret = DEFAULT.secret;
    const transactionStore = new TransactionStore({
      secret
    });
    const sessionStore = new StatelessSessionStore({
      secret
    });

    authClient = new AuthClient({
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
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("Organization Parameter Validation", () => {
    it("should accept valid organization parameter", async () => {
      const request = new NextRequest(
        "https://example.com/auth/login?organization=org_123",
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);

      const auth0Res = new Auth0NextResponse(NextResponse.next());

      await authClient.handleLogin(auth0Req, auth0Res);

      const response = auth0Res.res;

      expect(response.status).toBe(307); // Redirect to Auth0
      expect(response.headers.get("location")).toContain(
        "organization=org_123"
      );
    });

    it("should accept organization with underscores, hyphens, and dots", async () => {
      const request = new NextRequest(
        "https://example.com/auth/login?organization=org_test-123.dev",
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);

      const auth0Res = new Auth0NextResponse(NextResponse.next());

      await authClient.handleLogin(auth0Req, auth0Res);

      const response = auth0Res.res;

      expect(response.status).toBe(307);
      expect(response.headers.get("location")).toContain(
        "organization=org_test-123.dev"
      );
    });

    it("should pass through organization parameter with spaces (Auth0 server validates)", async () => {
      const request = new NextRequest(
        "https://example.com/auth/login?organization=org%20space",
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);

      const auth0Res = new Auth0NextResponse(NextResponse.next());

      await authClient.handleLogin(auth0Req, auth0Res);

      const response = auth0Res.res;

      expect(response.status).toBe(307); // Redirect to Auth0
      const location = response.headers.get("location");
      expect(location).toContain("organization=org+space");
    });

    it("should pass through organization parameter with special characters (Auth0 server validates)", async () => {
      const request = new NextRequest(
        "https://example.com/auth/login?organization=org<script>",
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);

      const auth0Res = new Auth0NextResponse(NextResponse.next());

      await authClient.handleLogin(auth0Req, auth0Res);

      const response = auth0Res.res;

      expect(response.status).toBe(307); // Redirect to Auth0
      const location = response.headers.get("location");
      expect(location).toContain("organization=");
    });

    it("should pass through long organization parameter (Auth0 server validates)", async () => {
      const longOrg = "org_" + "a".repeat(300);
      const request = new NextRequest(
        `https://example.com/auth/login?organization=${longOrg}`,
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);

      const auth0Res = new Auth0NextResponse(NextResponse.next());

      await authClient.handleLogin(auth0Req, auth0Res);

      const response = auth0Res.res;

      expect(response.status).toBe(307); // Redirect to Auth0
      const location = response.headers.get("location");
      expect(location).toContain("organization=");
    });

    it("should work without organization parameter", async () => {
      const request = new NextRequest("https://example.com/auth/login", {
        method: "GET"
      });

      const auth0Req = new Auth0NextRequest(request);

      const auth0Res = new Auth0NextResponse(NextResponse.next());

      await authClient.handleLogin(auth0Req, auth0Res);

      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("location");
      expect(location).not.toContain("organization=");
    });
  });

  describe("Static Configuration", () => {
    it("should support organization in static configuration", async () => {
      const authClientWithOrg = new AuthClient({
        transactionStore: new TransactionStore({ secret: DEFAULT.secret }),
        sessionStore: new StatelessSessionStore({ secret: DEFAULT.secret }),
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret: DEFAULT.secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        authorizationParameters: {
          organization: "org_static_123"
        },
        fetch: getMockAuthorizationServer()
      });

      const request = new NextRequest("https://example.com/auth/login", {
        method: "GET"
      });

      const auth0Req1 = new Auth0NextRequest(request);
      const auth0Res1 = new Auth0NextResponse(NextResponse.next());
      await authClientWithOrg.handleLogin(auth0Req1, auth0Res1);
      const response = auth0Res1.res;

      expect(response.status).toBe(307);
      expect(response.headers.get("location")).toContain(
        "organization=org_static_123"
      );
    });

    it("should allow URL parameter to override static configuration", async () => {
      const authClientWithOrg = new AuthClient({
        transactionStore: new TransactionStore({ secret: DEFAULT.secret }),
        sessionStore: new StatelessSessionStore({ secret: DEFAULT.secret }),
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret: DEFAULT.secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        authorizationParameters: {
          organization: "org_static_123"
        },
        fetch: getMockAuthorizationServer()
      });

      const request = new NextRequest(
        "https://example.com/auth/login?organization=org_override_456",
        {
          method: "GET"
        }
      );

      const auth0Req2 = new Auth0NextRequest(request);
      const auth0Res2 = new Auth0NextResponse(NextResponse.next());
      await authClientWithOrg.handleLogin(auth0Req2, auth0Res2);
      const response = auth0Res2.res;

      expect(response.status).toBe(307);
      // URL parameter should override static configuration
      expect(response.headers.get("location")).toContain(
        "organization=org_override_456"
      );
      expect(response.headers.get("location")).not.toContain(
        "organization=org_static_123"
      );
    });
  });

  describe("PAR (Pushed Authorization Requests) Mode", () => {
    it("should not forward organization parameter when PAR is enabled", async () => {
      const authClientWithPAR = new AuthClient({
        transactionStore: new TransactionStore({ secret: DEFAULT.secret }),
        sessionStore: new StatelessSessionStore({ secret: DEFAULT.secret }),
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        secret: DEFAULT.secret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        pushedAuthorizationRequests: true,
        fetch: getMockAuthorizationServer()
      });

      const request = new NextRequest(
        "https://example.com/auth/login?organization=org_123",
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);
      const auth0Res = new Auth0NextResponse(NextResponse.next());
      await authClientWithPAR.handleLogin(auth0Req, auth0Res);
      const response = auth0Res.res;

      expect(response.status).toBe(307);
      // With PAR enabled, query parameters should not be forwarded
      const location = response.headers.get("location");
      expect(location).not.toContain("organization=org_123");
    });
  });

  describe("Integration with Other Parameters", () => {
    it("should work alongside other authorization parameters", async () => {
      const request = new NextRequest(
        "https://example.com/auth/login?organization=org_123&audience=api.example.com&scope=openid%20profile",
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);

      const auth0Res = new Auth0NextResponse(NextResponse.next());

      await authClient.handleLogin(auth0Req, auth0Res);

      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("location");
      expect(location).toContain("organization=org_123");
      expect(location).toContain("audience=api.example.com");
      expect(location).toContain("scope=openid+profile");
    });

    it("should work with returnTo parameter", async () => {
      const request = new NextRequest(
        "https://example.com/auth/login?organization=org_123&returnTo=%2Fprotected",
        {
          method: "GET"
        }
      );

      const auth0Req = new Auth0NextRequest(request);

      const auth0Res = new Auth0NextResponse(NextResponse.next());

      await authClient.handleLogin(auth0Req, auth0Res);

      const response = auth0Res.res;

      expect(response.status).toBe(307);
      const location = response.headers.get("location");
      expect(location).toContain("organization=org_123");
    });
  });
});
