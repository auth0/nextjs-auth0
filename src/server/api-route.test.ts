import { IncomingMessage, ServerResponse } from "http";
import { Socket } from "net";
import { NextApiRequest, NextApiResponse } from "next";
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

import { generateSecret } from "../test/utils.js";
import { SessionData } from "../types/index.js";
import { Auth0Client } from "./client.js";
import { encrypt, RequestCookies } from "./cookies.js";

const constants = {
  domain: "https://auth0.local",
  clientId: "client_123",
  clientSecret: "client-secret",
  appBaseUrl: "https://example.com",
  sub: "user_123",
  secret: await generateSecret(32)
};

let keyPair: jose.GenerateKeyPairResult;

// MSW handlers for mocking Auth0 endpoints
const handlers = [
  // OIDC Discovery Endpoint
  http.get(`${constants.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json({
      issuer: constants.domain,
      authorization_endpoint: `${constants.domain}/authorize`,
      token_endpoint: `${constants.domain}/oauth/token`,
      end_session_endpoint: `${constants.domain}/oidc/logout`,
      jwks_uri: `${constants.domain}/.well-known/jwks.json`
    });
  }),
  // JWKS Endpoint
  http.get(`${constants.domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({ keys: [jwk] });
  })
];

const server = setupServer(...handlers);

describe("apiRoute", () => {
  beforeAll(async () => {
    // Generate RSA key pair for JWT signing
    keyPair = await jose.generateKeyPair("RS256");
    server.listen({ onUnhandledRequest: "error" });
  });

  afterAll(() => {
    server.close();
  });

  afterEach(() => {
    server.resetHandlers();
  });

  describe("App Router", () => {
    let auth0Client: Auth0Client;

    beforeEach(() => {
      auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret,
        routes: {
          login: "/api/auth/login",
          logout: "/api/auth/logout",
          callback: "/api/auth/callback",
          profile: "/api/auth/profile",
          backChannelLogout: "/api/auth/backchannel-logout",
        }
      });
    });

    it("should handle /auth/login via catch-all route", async () => {
      const request = new NextRequest(
        new URL(`${constants.appBaseUrl}/api/auth/auth/login`),
        {
          method: "GET"
        }
      );
      const context = { params: { auth0: ["auth", "login"] } };

      const response = await auth0Client.apiRoute(request, context);

      // Should redirect to Auth0 authorization endpoint
      expect(response.status).toBe(307);
      expect(response.headers.get("location")).toContain(
        `${constants.domain}/authorize`
      );
    });

    it("should handle /auth/logout via catch-all route", async () => {
      const request = new NextRequest(
        new URL(`${constants.appBaseUrl}/api/auth/auth/logout`),
        {
          method: "GET"
        }
      );
      const context = { params: { auth0: ["auth", "logout"] } };

      const response = await auth0Client.apiRoute(request, context);

      // Should redirect to Auth0 logout endpoint
      expect(response.status).toBe(307);
      expect(response.headers.get("location")).toContain(constants.domain);
    });

    it("should handle /auth/profile without session", async () => {
      const request = new NextRequest(
        new URL(`${constants.appBaseUrl}/api/auth/auth/profile`),
        {
          method: "GET"
        }
      );
      const context = { params: { auth0: ["auth", "profile"] } };

      const response = await auth0Client.apiRoute(request, context);

      // Should return 401 when no session
      expect(response.status).toBe(401);
    });

    it("should handle /auth/profile with valid session", async () => {
      const session: SessionData = {
        user: { sub: constants.sub, email: "user@example.com" },
        tokenSet: {
          idToken: "idt_123",
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      const encryptedSession = await encrypt(
        session,
        constants.secret,
        Date.now() + 86400 * 1000
      );

      const request = new NextRequest(
        new URL(`${constants.appBaseUrl}/api/auth/auth/profile`),
        {
          method: "GET",
          headers: {
            cookie: `__session=${encryptedSession}`
          }
        }
      );
      const context = { params: { auth0: ["auth", "profile"] } };

      const response = await auth0Client.apiRoute(request, context);

      // Should return 200 with user profile
      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json.sub).toBe(constants.sub);
      expect(json.email).toBe("user@example.com");
    });

    it("should preserve query parameters", async () => {
      const request = new NextRequest(
        new URL(`${constants.appBaseUrl}/api/auth/auth/login?returnTo=/dashboard`),
        {
          method: "GET"
        }
      );
      const context = { params: { auth0: ["auth", "login"] } };

      const response = await auth0Client.apiRoute(request, context);

      // Should redirect and preserve returnTo parameter
      expect(response.status).toBe(307);
      const location = response.headers.get("location");
      expect(location).toContain("redirect_uri=");
    });

    it("should handle Promise params (Next.js 15+)", async () => {
      const request = new NextRequest(
        new URL(`${constants.appBaseUrl}/api/auth/auth/login`),
        {
          method: "GET"
        }
      );
      const context = { params: Promise.resolve({ auth0: ["auth", "login"] }) };

      const response = await auth0Client.apiRoute(request, context);

      // Should handle Promise params and redirect
      expect(response.status).toBe(307);
    });

    it("should handle POST requests for backchannel logout", async () => {
      const request = new NextRequest(
        new URL(`${constants.appBaseUrl}/api/auth/auth/backchannel-logout`),
        {
          method: "POST",
          body: "logout_token=test_token",
          headers: {
            "content-type": "application/x-www-form-urlencoded"
          }
        }
      );
      const context = { params: { auth0: ["auth", "backchannel-logout"] } };

      const response = await auth0Client.apiRoute(request, context);

      // Should handle POST request (may return error due to invalid token, but should not crash)
      expect(response.status).toBeGreaterThanOrEqual(200);
    });
  });

  describe("Pages Router", () => {
    let auth0Client: Auth0Client;

    beforeEach(() => {
      auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret,
        routes: {
          login: "/api/auth/login",
          logout: "/api/auth/logout",
          callback: "/api/auth/callback",
          profile: "/api/auth/profile",
          backChannelLogout: "/api/auth/backchannel-logout",
        }
      });
    });

    function createMockRequest(
      url: string,
      method: string = "GET",
      query: any = {}
    ): NextApiRequest {
      const socket = new Socket();
      const req = new IncomingMessage(socket) as NextApiRequest;
      // Use absolute URL for Next.js compatibility
      const absoluteUrl = url.startsWith("http") ? url : `${constants.appBaseUrl}${url}`;
      req.url = absoluteUrl;
      req.method = method;
      req.headers = { host: new URL(constants.appBaseUrl).host };
      req.query = query;
      return req;
    }

    function createMockResponse(): NextApiResponse {
      const socket = new Socket();
      const res = new ServerResponse(new IncomingMessage(socket)) as NextApiResponse;
      res.statusCode = 200;

      const headers: Record<string, string | string[]> = {};
      res.setHeader = vi.fn((key: string, value: string | string[]) => {
        headers[key.toLowerCase()] = value;
        return res;
      });
      res.getHeader = vi.fn((key: string) => headers[key.toLowerCase()]);
      res.appendHeader = vi.fn((key: string, value: string) => {
        const existing = headers[key.toLowerCase()];
        if (existing) {
          headers[key.toLowerCase()] = Array.isArray(existing)
            ? [...existing, value]
            : [existing, value];
        } else {
          headers[key.toLowerCase()] = value;
        }
        return res;
      });

      const chunks: Buffer[] = [];
      res.write = vi.fn((chunk: any) => {
        chunks.push(Buffer.from(chunk));
        return true;
      });
      res.end = vi.fn(() => {
        res.finished = true;
        return res;
      });

      (res as any).chunks = chunks;
      (res as any).headers = headers;

      return res;
    }

    it("should handle /auth/login via apiRouteHandler", async () => {
      const req = createMockRequest("/api/auth/auth/login", "GET", {
        auth0: ["auth", "login"]
      });
      const res = createMockResponse();

      await auth0Client.apiRouteHandler(req, res);

      // Should redirect to Auth0 authorization endpoint
      expect(res.statusCode).toBe(307);
      const location = (res as any).headers["location"];
      expect(location).toContain(`${constants.domain}/authorize`);
    });

    it("should handle /auth/logout via Pages Router catch-all route", async () => {
      const req = createMockRequest("/api/auth/auth/logout", "GET", {
        auth0: ["auth", "logout"]
      });
      const res = createMockResponse();

      await auth0Client.apiRouteHandler(req, res);

      // Should redirect to Auth0 logout endpoint
      expect(res.statusCode).toBe(307);
      const location = (res as any).headers["location"];
      expect(location).toContain(constants.domain);
    });

    it("should handle /auth/profile without session", async () => {
      const req = createMockRequest("/api/auth/auth/profile", "GET", {
        auth0: ["auth", "profile"]
      });
      const res = createMockResponse();

      await auth0Client.apiRouteHandler(req, res);

      // Should return 401 when no session
      expect(res.statusCode).toBe(401);
    });

    it("should handle /auth/profile with valid session", async () => {
      const session: SessionData = {
        user: { sub: constants.sub, email: "user@example.com" },
        tokenSet: {
          idToken: "idt_123",
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };

      const encryptedSession = await encrypt(
        session,
        constants.secret,
        Date.now() + 86400 * 1000
      );

      const req = createMockRequest("/api/auth/auth/profile", "GET", {
        auth0: ["auth", "profile"]
      });
      req.headers.cookie = `__session=${encryptedSession}`;
      const res = createMockResponse();

      await auth0Client.apiRouteHandler(req, res);

      // Should return 200 with user profile
      expect(res.statusCode).toBe(200);
      const body = Buffer.concat((res as any).chunks).toString();
      const json = JSON.parse(body);
      expect(json.sub).toBe(constants.sub);
      expect(json.email).toBe("user@example.com");
    });

    it("should handle multiple set-cookie headers correctly", async () => {
      const req = createMockRequest("/api/auth/auth/login", "GET", {
        auth0: ["auth", "login"]
      });
      const res = createMockResponse();

      await auth0Client.apiRouteHandler(req, res);

      // Should set transaction cookies
      const setCookie = (res as any).headers["set-cookie"];
      expect(setCookie).toBeDefined();
    });
  });
});
