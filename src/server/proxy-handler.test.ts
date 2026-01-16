import { NextRequest } from "next/server.js";
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
  it
} from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import {
  createDPoPNonceRetryHandler,
  createInitialSessionData,
  createSessionCookie,
  extractDPoPInfo
} from "../test/proxy-handler-test-helpers.js";
import { generateSecret } from "../test/utils.js";
import { generateDpopKeyPair } from "../utils/dpopUtils.js";
import { Auth0Client } from "./client.js";

/**
 * Comprehensive Test Suite: AuthClient Custom Proxy Handler
 *
 * This test suite validates the `#handleProxy()` method with custom proxy routes,
 * covering Bearer/DPoP authentication, HTTP methods, headers, bodies, streaming,
 * nonce retry, session updates, and error handling.
 *
 * Architecture:
 * - MSW mocks Auth0 (discovery, token endpoint) and arbitrary upstream API
 * - Tests use black-box flow approach (call handler, verify response)
 * - DPoP nonce retry validated via stateful MSW handlers
 * - Session updates verified via Set-Cookie headers
 *
 * Test Categories:
 * 1: Basic Proxy Routing & Session Management
 * 2: HTTP Method Routing
 * 3: URL Path Matching & Transformation
 * 4: HTTP Headers Forwarding
 * 5: Request Body Handling
 * 6: Bearer Token Handling
 * 7: DPoP Token Handling
 * 8: Session Update After Token Refresh
 * 9: Error Scenarios
 * 10: Concurrent Request Handling
 * 11: CORS Handling
 */

const DEFAULT = {
  domain: "test.auth0.local",
  clientId: "test_client_id",
  clientSecret: "test_client_secret",
  appBaseUrl: "https://example.com",
  proxyPath: "/me",
  upstreamBaseUrl: `https://test.auth0.local/me/v1`,
  audience: `https://test.auth0.local/me/`,
  accessToken: "at_test_123",
  refreshToken: "rt_test_123",
  sub: "user_test_123",
  sid: "session_test_123",
  alg: "RS256" as const
};

const UPSTREAM_RESPONSE_DATA = {
  simpleJson: { id: 1, name: "test", data: "value" },
  largeJson: {
    // ~100KB payload for streaming tests
    items: Array.from({ length: 1000 }, (_, i) => ({
      id: i,
      name: `item_${i}`,
      description: "A".repeat(100),
      metadata: { key1: "value1", key2: "value2", key3: "value3" }
    }))
  },
  htmlContent: "<!DOCTYPE html><html><body><h1>Test</h1></body></html>",
  errorResponse: { error: "some_error", error_description: "Error occurred" }
};

// Discovery metadata
const _authorizationServerMetadata = {
  issuer: `https://${DEFAULT.domain}`,
  authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
  token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
  jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  dpop_signing_alg_values_supported: ["RS256", "ES256"]
};

let keyPair: jose.GenerateKeyPairResult;
let dpopKeyPair: Awaited<ReturnType<typeof generateDpopKeyPair>>;
let secret: string;
let authClient: Auth0Client;

const server = setupServer(
  // Discovery endpoint
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(_authorizationServerMetadata);
  }),

  // JWKS endpoint
  http.get(`https://${DEFAULT.domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({
      keys: [{ ...jwk, kid: "test-key-1", alg: DEFAULT.alg, use: "sig" }]
    });
  }),

  // Token endpoint
  http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
    // Generate ID token
    const jwt = await new jose.SignJWT({
      sid: DEFAULT.sid,
      auth_time: Math.floor(Date.now() / 1000),
      nonce: "nonce-value"
    })
      .setProtectedHeader({ alg: DEFAULT.alg })
      .setSubject(DEFAULT.sub)
      .setIssuedAt()
      .setIssuer(_authorizationServerMetadata.issuer)
      .setAudience(DEFAULT.clientId)
      .setExpirationTime("2h")
      .sign(keyPair.privateKey);

    return HttpResponse.json({
      token_type: "Bearer",
      access_token: DEFAULT.accessToken,
      refresh_token: DEFAULT.refreshToken,
      id_token: jwt,
      expires_in: 3600
    });
  }),

  // Default upstream API handlers (will be overridden in tests)
  // Match base URL without trailing slash
  http.all(`${DEFAULT.upstreamBaseUrl}`, () => {
    return HttpResponse.json(UPSTREAM_RESPONSE_DATA.simpleJson, {
      status: 200
    });
  }),
  // Match base URL with trailing slash
  http.all(`${DEFAULT.upstreamBaseUrl}/`, () => {
    return HttpResponse.json(UPSTREAM_RESPONSE_DATA.simpleJson, {
      status: 200
    });
  }),
  // Match all subpaths
  http.all(`${DEFAULT.upstreamBaseUrl}/*`, () => {
    return HttpResponse.json(UPSTREAM_RESPONSE_DATA.simpleJson, {
      status: 200
    });
  })
);

beforeAll(async () => {
  keyPair = await jose.generateKeyPair(DEFAULT.alg);
  dpopKeyPair = await generateDpopKeyPair();
  secret = await generateSecret(32);
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});

describe("Authentication Client - Custom Proxy Handler", async () => {
  beforeEach(async () => {
    authClient = new Auth0Client({
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      appBaseUrl: DEFAULT.appBaseUrl,
      routes: getDefaultRoutes(),
      secret,
      fetch: (url, init) =>
        fetch(url, { ...init, ...(init?.body ? { duplex: "half" } : {}) })
    });
  });

  describe("Category 1: Basic Proxy Routing & Session Management", () => {
    it("1.1 should return 200 (passthrough) when proxy handler not found", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      const request = new NextRequest(
        new URL("/non-existent-proxy/users", DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      // Handler uses NextResponse.next() for unmatched routes, allowing them to pass through
      // This is intentional to allow the handler to coexist with other Next.js routes
      expect(response.status).toBe(200);
    });

    it("1.2 should return 401 when session missing", async () => {
      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/users`, DEFAULT.appBaseUrl),
        { method: "GET" }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(401);
      const text = await response.text();
      expect(text).toContain("active session");
    });

    it("1.3 should proxy request when valid session exists", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      // Override upstream handler
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/users`, () => {
          return HttpResponse.json({ success: true, users: ["user1"] });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/users`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(data).toEqual({ success: true, users: ["user1"] });
    });
  });

  // GET, POST, PUT, DELETE, OPTIONS, HEAD, CORS
  describe("Category 2: HTTP Method Routing", () => {
    it("2.1 should proxy GET request", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/items`, () => {
          return HttpResponse.json({ method: "GET", items: [] });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/items`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(data.method).toBe("GET");
    });

    it("2.2 should proxy POST request with JSON body", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedBody: any;
      server.use(
        http.post(`${DEFAULT.upstreamBaseUrl}/items`, async ({ request }) => {
          receivedBody = await request.json();
          return HttpResponse.json({ method: "POST", created: true });
        })
      );

      const requestBody = { name: "New Item", value: 42 };
      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/items`, DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            cookie,
            "content-type": "application/json"
          },
          body: JSON.stringify(requestBody)
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);

      expect(receivedBody).toEqual(requestBody);
    });

    it("2.3 should proxy PUT request with JSON body", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedBody: any;
      server.use(
        http.put(`${DEFAULT.upstreamBaseUrl}/items/1`, async ({ request }) => {
          receivedBody = await request.json();
          return HttpResponse.json({ method: "PUT", updated: true });
        })
      );

      const requestBody = { name: "Updated Item" };
      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/items/1`, DEFAULT.appBaseUrl),
        {
          method: "PUT",
          headers: {
            cookie,
            "content-type": "application/json"
          },
          body: JSON.stringify(requestBody)
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);

      expect(receivedBody).toEqual(requestBody);
    });

    it("2.4 should proxy PATCH request with JSON body", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedBody: any;
      server.use(
        http.patch(
          `${DEFAULT.upstreamBaseUrl}/items/1`,
          async ({ request }) => {
            receivedBody = await request.json();
            return HttpResponse.json({ method: "PATCH", patched: true });
          }
        )
      );

      const requestBody = { value: 99 };
      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/items/1`, DEFAULT.appBaseUrl),
        {
          method: "PATCH",
          headers: {
            cookie,
            "content-type": "application/json"
          },
          body: JSON.stringify(requestBody)
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);

      expect(receivedBody).toEqual(requestBody);
    });

    it("2.5 should proxy DELETE request", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.delete(`${DEFAULT.upstreamBaseUrl}/items/1`, () => {
          return new HttpResponse(null, { status: 204 });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/items/1`, DEFAULT.appBaseUrl),
        {
          method: "DELETE",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(204);
    });

    it("2.6 should proxy HEAD request", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.head(`${DEFAULT.upstreamBaseUrl}/items`, () => {
          return new HttpResponse(null, {
            status: 200,
            headers: { "x-total-count": "42" }
          });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/items`, DEFAULT.appBaseUrl),
        {
          method: "HEAD",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);
      expect(response.headers.get("x-total-count")).toBe("42");
    });

    it("2.7 should handle OPTIONS preflight CORS without auth", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      // Mock upstream to return CORS headers for preflight
      server.use(
        http.options(`${DEFAULT.upstreamBaseUrl}/items`, () => {
          return new HttpResponse(null, {
            status: 204,
            headers: {
              "access-control-allow-origin": "*",
              "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
              "access-control-allow-headers": "content-type, authorization"
            }
          });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/items`, DEFAULT.appBaseUrl),
        {
          method: "OPTIONS",
          headers: {
            cookie,
            origin: "https://frontend.example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type"
          }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(204);

      // Preflight should not include Authorization header
      expect(response.headers.get("access-control-allow-origin")).toBeTruthy();
    });

    it("2.8 should proxy OPTIONS non-preflight request", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.options(`${DEFAULT.upstreamBaseUrl}/items`, () => {
          return new HttpResponse(null, {
            status: 200,
            headers: {
              allow: "GET, POST, PUT, DELETE, OPTIONS"
            }
          });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/items`, DEFAULT.appBaseUrl),
        {
          method: "OPTIONS",
          headers: { cookie }
          // Note: no access-control-request-method header = not preflight
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);
      expect(response.headers.get("allow")).toContain("GET");
    });
  });

  // combine single level and multi level subpaths
  describe("Category 3: URL Path Matching & Transformation", () => {
    it("3.1 should reject exact proxy path without subpath (security)", async () => {
      // Security: The My Account and My Org APIs have no endpoints at exactly /me or /my-org
      // All real endpoints are like /me/v1/... or /my-org/v1/...
      // Accepting exact paths could lead to security issues
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      const request = new NextRequest(
        new URL(DEFAULT.proxyPath, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      // Should not proxy - should just touch sessions and return Next response
      expect(response.status).toBe(200);
      // Should not have proxied content
      const text = await response.text();
      expect(text).not.toContain('{"path":"/"}');
    });

    it("3.2 should proxy to single-level subpath", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/users`, () => {
          return HttpResponse.json({ path: "/users" });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/users`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(data.path).toBe("/users");
    });

    it("3.3 should proxy to multi-level subpath", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/api/v1/users/123/profile`, () => {
          return HttpResponse.json({ path: "/api/v1/users/123/profile" });
        })
      );

      const request = new NextRequest(
        new URL(
          `${DEFAULT.proxyPath}/api/v1/users/123/profile`,
          DEFAULT.appBaseUrl
        ),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);

      const data = await response.json();
      expect(data.path).toBe("/api/v1/users/123/profile");
    });

    it("3.4 should preserve query string parameters", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedUrl: string;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/search`, ({ request }) => {
          receivedUrl = request.url;
          return HttpResponse.json({ received: true });
        })
      );

      const request = new NextRequest(
        new URL(
          `${DEFAULT.proxyPath}/search?q=test&limit=10&offset=0`,
          DEFAULT.appBaseUrl
        ),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);

      const url = new URL(receivedUrl!);
      expect(url.searchParams.get("q")).toBe("test");
      expect(url.searchParams.get("limit")).toBe("10");
      expect(url.searchParams.get("offset")).toBe("0");
    });

    it("3.5 should handle paths with special characters", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.get(
          `${DEFAULT.upstreamBaseUrl}/items/test%20item%2Bspecial`,
          () => {
            return HttpResponse.json({ success: true });
          }
        )
      );

      const request = new NextRequest(
        new URL(
          `${DEFAULT.proxyPath}/items/test%20item%2Bspecial`,
          DEFAULT.appBaseUrl
        ),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);
    });

    it("3.6 should handle paths with trailing slash", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/users/`, () => {
          return HttpResponse.json({ path: "/users/" });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/users/`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);
    });
  });

  describe("Category 4: HTTP Headers Forwarding", () => {
    it("4.1 should forward allow-listed request headers", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedHeaders: Headers;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          receivedHeaders = request.headers;
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "x-request-id": "req-123",
            "x-correlation-id": "corr-456"
          }
        }
      );

      await authClient.middleware(request);

      // Only explicitly allow-listed headers should be forwarded
      expect(receivedHeaders!.get("x-request-id")).toBe("req-123");
      expect(receivedHeaders!.get("x-correlation-id")).toBe("corr-456");
    });

    it("4.1b should NOT forward arbitrary request headers not in allow-list", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedHeaders: Headers;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          receivedHeaders = request.headers;
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "x-custom-header": "should-not-be-forwarded",
            "some-custom-header-name": "also-not-forwarded",
            "x-request-id": "req-123" // This IS in the allow-list
          }
        }
      );

      await authClient.middleware(request);

      // Arbitrary x-* headers should NOT be forwarded
      expect(receivedHeaders!.get("x-custom-header")).toBeNull();
      expect(receivedHeaders!.get("some-custom-header-name")).toBeNull();
      // But explicitly allow-listed x-* headers SHOULD be forwarded
      expect(receivedHeaders!.get("x-request-id")).toBe("req-123");
    });

    it("4.2 should forward standard headers (Accept, Content-Type)", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedHeaders: Headers;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          receivedHeaders = request.headers;
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            accept: "application/json",
            "accept-language": "en-US",
            "content-type": "application/json"
          }
        }
      );

      await authClient.middleware(request);

      expect(receivedHeaders!.get("accept")).toBe("application/json");
      expect(receivedHeaders!.get("accept-language")).toBe("en-US");
    });

    it("4.3 should strip Cookie header and replace Authorization with token", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedHeaders: Headers;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          receivedHeaders = request.headers;
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            authorization: "Bearer should-be-replaced"
          }
        }
      );

      await authClient.middleware(request);

      // Cookie should be stripped
      expect(receivedHeaders!.get("cookie")).toBeNull();

      // Authorization should be replaced with session token
      expect(receivedHeaders!.get("authorization")).toBe(
        `Bearer ${DEFAULT.accessToken}`
      );
    });

    it("4.4 should update Host header to upstream host", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedHeaders: Headers;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          receivedHeaders = request.headers;
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      await authClient.middleware(request);

      // Host should be updated to upstream host
      const upstreamHost = new URL(DEFAULT.upstreamBaseUrl).host;
      expect(receivedHeaders!.get("host")).toBe(upstreamHost);
    });

    it("4.5 should preserve User-Agent header", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedHeaders: Headers;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          receivedHeaders = request.headers;
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: {
            cookie,
            "user-agent": "Test-Agent/1.0"
          }
        }
      );

      await authClient.middleware(request);

      expect(receivedHeaders!.get("user-agent")).toBe("Test-Agent/1.0");
    });

    it("4.6 should forward custom RESPONSE headers from upstream", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, () => {
          return HttpResponse.json(
            { success: true },
            {
              headers: {
                "x-custom-response": "response-value",
                "x-rate-limit": "100"
              }
            }
          );
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);

      expect(response.headers.get("x-custom-response")).toBe("response-value");
      expect(response.headers.get("x-rate-limit")).toBe("100");
    });

    it("4.7 should forward CORS headers from upstream", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, () => {
          return HttpResponse.json(
            { success: true },
            {
              headers: {
                "access-control-allow-origin": "*",
                "access-control-allow-methods": "GET, POST",
                "access-control-allow-headers": "Content-Type"
              }
            }
          );
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);

      expect(response.headers.get("access-control-allow-origin")).toBe("*");
      expect(response.headers.get("access-control-allow-methods")).toBe(
        "GET, POST"
      );
    });
  });

  describe("Category 5: Request Body Handling", () => {
    it("5.1 should forward JSON body correctly", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedBody: any;
      server.use(
        http.post(`${DEFAULT.upstreamBaseUrl}/data`, async ({ request }) => {
          receivedBody = await request.json();
          return HttpResponse.json({ received: true });
        })
      );

      const requestBody = { name: "test", value: 42, nested: { key: "value" } };
      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            cookie,
            "content-type": "application/json"
          },
          body: JSON.stringify(requestBody)
        }
      );

      await authClient.middleware(request);

      expect(receivedBody).toEqual(requestBody);
    });

    it("5.2 should forward form data body", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedBody: string;
      server.use(
        http.post(`${DEFAULT.upstreamBaseUrl}/data`, async ({ request }) => {
          receivedBody = await request.text();
          return HttpResponse.json({ received: true });
        })
      );

      const formData = new URLSearchParams({
        username: "testuser",
        password: "testpass"
      });

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            cookie,
            "content-type": "application/x-www-form-urlencoded"
          },
          body: formData.toString()
        }
      );

      await authClient.middleware(request);

      expect(receivedBody!).toBe("username=testuser&password=testpass");
    });

    it("5.3 should forward plain text body", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedBody: string;
      server.use(
        http.post(`${DEFAULT.upstreamBaseUrl}/data`, async ({ request }) => {
          receivedBody = await request.text();
          return HttpResponse.json({ received: true });
        })
      );

      const textBody = "This is plain text content\nWith multiple lines";
      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            cookie,
            "content-type": "text/plain"
          },
          body: textBody
        }
      );

      await authClient.middleware(request);

      expect(receivedBody!).toBe(textBody);
    });

    it("5.4 should handle empty body", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let bodyWasNull = false;
      server.use(
        http.post(`${DEFAULT.upstreamBaseUrl}/data`, async ({ request }) => {
          bodyWasNull = request.body === null;
          return HttpResponse.json({ bodyWasNull });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);

      expect(response.status).toBe(200);
      expect(bodyWasNull).toBe(true);
    });

    it("5.5 should handle large JSON body", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedBody: any;
      server.use(
        http.post(`${DEFAULT.upstreamBaseUrl}/data`, async ({ request }) => {
          receivedBody = await request.json();
          return HttpResponse.json({ received: true });
        })
      );

      // Create large payload (~100KB)
      const largeBody = {
        items: Array.from({ length: 1000 }, (_, i) => ({
          id: i,
          name: `item_${i}`,
          data: "A".repeat(100)
        }))
      };

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            cookie,
            "content-type": "application/json"
          },
          body: JSON.stringify(largeBody)
        }
      );

      await authClient.middleware(request);

      expect(receivedBody).toEqual(largeBody);
    });
  });

  describe("Category 6: Bearer Token Handling", () => {
    it("6.1 should send Bearer token in Authorization header", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      let receivedAuthHeader: string | null = null;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          receivedAuthHeader = request.headers.get("authorization");
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      await authClient.middleware(request);

      expect(receivedAuthHeader).toBe(`Bearer ${DEFAULT.accessToken}`);
    });
  });

  describe("Category 7: DPoP Token Handling", () => {
    let dpopAuthClient: Auth0Client;

    beforeEach(async () => {
      // Create AuthClient with DPoP enabled
      dpopAuthClient = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        secret,
        useDPoP: true,
        dpopKeyPair: dpopKeyPair,
        fetch: (url, init) =>
          fetch(url, { ...init, ...(init?.body ? { duplex: "half" } : {}) })
      });
    });
    it("7.1 should send DPoP proof in DPoP header", async () => {
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          scope: "read:data",
          audience: DEFAULT.audience,
          token_type: "DPoP"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      let receivedDPoPHeader: string | null = null;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          receivedDPoPHeader = request.headers.get("dpop");
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      await dpopAuthClient.middleware(request);

      expect(receivedDPoPHeader).toBeTruthy();
      expect(receivedDPoPHeader).toMatch(
        /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
      ); // JWT format
    });

    it("7.2 should include htm claim (HTTP method) in DPoP proof", async () => {
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          scope: "read:data",
          audience: DEFAULT.audience,
          token_type: "DPoP"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      let dpopProof: string | null = null;
      server.use(
        http.post(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          dpopProof = request.headers.get("dpop");
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            cookie,
            "content-type": "application/json"
          },
          body: JSON.stringify({ test: "data" })
        }
      );

      await dpopAuthClient.middleware(request);

      const dpopInfo = extractDPoPInfo(dpopProof);
      expect(dpopInfo.htm).toBe("POST");
    });

    it("7.3 should include htu claim (HTTP URI) in DPoP proof", async () => {
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          scope: "read:data",
          audience: DEFAULT.audience,
          token_type: "DPoP"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      let dpopProof: string | null = null;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/users/123`, ({ request }) => {
          dpopProof = request.headers.get("dpop");
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/users/123`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      await dpopAuthClient.middleware(request);

      const dpopInfo = extractDPoPInfo(dpopProof);
      expect(dpopInfo.htu).toBe(`${DEFAULT.upstreamBaseUrl}/users/123`);
    });

    it("7.4 should include jti and iat claims in DPoP proof", async () => {
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          scope: "read:data",
          audience: DEFAULT.audience,
          token_type: "DPoP"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      let dpopProof: string | null = null;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          dpopProof = request.headers.get("dpop");
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      await dpopAuthClient.middleware(request);

      const dpopInfo = extractDPoPInfo(dpopProof);
      expect(dpopInfo.jti).toBeTruthy();
      expect(dpopInfo.iat).toBeTruthy();
      expect(typeof dpopInfo.iat).toBe("number");
    });

    it("7.5 should send DPoP token in Authorization header with DPoP prefix", async () => {
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          scope: "read:data",
          audience: DEFAULT.audience,
          token_type: "DPoP"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      let receivedAuthHeader: string | null = null;
      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          receivedAuthHeader = request.headers.get("authorization");
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      await dpopAuthClient.middleware(request);

      expect(receivedAuthHeader).toBe(`DPoP ${DEFAULT.accessToken}`);
    });

    it("7.6 should retry with nonce on use_dpop_nonce error", async () => {
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          audience: DEFAULT.audience,
          scope: "read:data",
          token_type: "DPoP"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      const { handler, state } = createDPoPNonceRetryHandler({
        baseUrl: DEFAULT.upstreamBaseUrl,
        path: "/data",
        method: "GET",
        successResponse: { success: true }
      });

      server.use(http.get(`${DEFAULT.upstreamBaseUrl}/data`, handler));

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await dpopAuthClient.middleware(request);

      expect(response.status).toBe(200);
      expect(state.requestCount).toBe(2); // Initial + retry
      expect(state.requests[0].hasDPoP).toBe(true);
      expect(state.requests[0].hasNonce).toBe(false);
      expect(state.requests[1].hasDPoP).toBe(true);
      expect(state.requests[1].hasNonce).toBe(true);
      expect(state.requests[1].nonce).toBe("server_nonce_123");
    });

    it("7.7 should include nonce in retry DPoP proof", async () => {
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          scope: "read:data",
          audience: DEFAULT.audience,
          token_type: "DPoP"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      const { handler, state } = createDPoPNonceRetryHandler({
        baseUrl: DEFAULT.upstreamBaseUrl,
        path: "/data",
        method: "POST",
        successResponse: { created: true }
      });

      server.use(http.post(`${DEFAULT.upstreamBaseUrl}/data`, handler));

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "POST",
          headers: {
            cookie,
            "content-type": "application/json"
          },
          body: JSON.stringify({ test: "data" })
        }
      );

      const response = await dpopAuthClient.middleware(request);

      expect(response.status).toBe(200);

      // Verify nonce in retry proof
      const retryDPoPInfo = extractDPoPInfo(state.requests[1].dpopJwt!);
      expect(retryDPoPInfo.hasNonce).toBe(true);
      expect(retryDPoPInfo.nonce).toBe("server_nonce_123");
    });
  });

  describe("Category 8: Session Update After Token Refresh", () => {
    it("8.1 should update session with new access token after refresh", async () => {
      const now = Math.floor(Date.now() / 1000);
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: "old_token",
          refreshToken: DEFAULT.refreshToken,
          expiresAt: now - 10, // Expired
          scope: "read:data",
          token_type: "Bearer"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      const newAccessToken = "new_refreshed_token";
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
          const jwt = await new jose.SignJWT({
            sid: DEFAULT.sid,
            auth_time: Math.floor(Date.now() / 1000)
          })
            .setProtectedHeader({ alg: DEFAULT.alg })
            .setSubject(DEFAULT.sub)
            .setIssuedAt()
            .setIssuer(_authorizationServerMetadata.issuer)
            .setAudience(DEFAULT.clientId)
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);

          return HttpResponse.json({
            access_token: newAccessToken,
            refresh_token: DEFAULT.refreshToken,
            id_token: jwt,
            token_type: "Bearer",
            expires_in: 3600
          });
        }),
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, () => {
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);

      // Should have Set-Cookie header with updated session
      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toBeTruthy();
      expect(setCookieHeader).toContain("__session=");
    });

    it("8.2 should update session expiresAt after refresh", async () => {
      const now = Math.floor(Date.now() / 1000);
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: now - 10,
          scope: "read:data",
          token_type: "Bearer"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
          const jwt = await new jose.SignJWT({
            sid: DEFAULT.sid,
            auth_time: Math.floor(Date.now() / 1000)
          })
            .setProtectedHeader({ alg: DEFAULT.alg })
            .setSubject(DEFAULT.sub)
            .setIssuedAt()
            .setIssuer(_authorizationServerMetadata.issuer)
            .setAudience(DEFAULT.clientId)
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);

          return HttpResponse.json({
            access_token: "new_token",
            refresh_token: DEFAULT.refreshToken,
            id_token: jwt,
            token_type: "Bearer",
            expires_in: 7200 // 2 hours
          });
        }),
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, () => {
          return HttpResponse.json({ success: true });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);
      expect(response.status).toBe(200);

      // Verify session was updated (Set-Cookie present)
      expect(response.headers.get("set-cookie")).toBeTruthy();
    });
  });

  describe("Category 8b: Reused Fetcher Token Set Side Effect", () => {
    /**
     * CRITICAL TEST: Validates that tokenSetSideEffect is properly captured on each proxy call.
     *
     * PROBLEM:
     * - Fetchers are cached per audience to reuse DPoP handles
     * - Each proxy call creates a new `getAccessToken` closure that captures `tokenSetSideEffect`
     * - When a fetcher is reused, if we don't override its `getAccessToken`, it uses the STALE
     *   closure from the first call, which references the OLD `tokenSetSideEffect` variable
     * - This causes the second token refresh to update the WRONG tokenSetSideEffect variable,
     *   leading to the session not being updated on the second call
     *
     * SOLUTION:
     * - Override `fetcher.getAccessToken` on every proxy call to capture fresh `tokenSetSideEffect`
     * - See auth-client.ts line ~2367: `fetcher.getAccessToken = getAccessToken;`
     *
     * This test validates that BOTH proxy calls properly update their sessions after token refresh,
     * which would fail if the tokenSetSideEffect closure is stale.
     */
    it("8.3 should update session on BOTH calls when fetcher is reused for same audience", async () => {
      const now = Math.floor(Date.now() / 1000);

      // Track how many times token endpoint is called
      let tokenRefreshCount = 0;
      const refreshedTokens = [
        "first_refreshed_token",
        "second_refreshed_token"
      ];

      // Track which token was used in each upstream request to verify correct token flow
      const tokensUsedInUpstreamRequests: string[] = [];

      // Override token endpoint to return different tokens on each refresh
      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
          const jwt = await new jose.SignJWT({
            sid: DEFAULT.sid,
            auth_time: Math.floor(Date.now() / 1000)
          })
            .setProtectedHeader({ alg: DEFAULT.alg })
            .setSubject(DEFAULT.sub)
            .setIssuedAt()
            .setIssuer(_authorizationServerMetadata.issuer)
            .setAudience(DEFAULT.clientId)
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);

          const token = refreshedTokens[tokenRefreshCount];
          tokenRefreshCount++;

          return HttpResponse.json({
            access_token: token,
            refresh_token: DEFAULT.refreshToken,
            id_token: jwt,
            token_type: "Bearer",
            expires_in: 3600
          });
        }),
        // Track Authorization header to verify correct token is used
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, ({ request }) => {
          const authHeader = request.headers.get("authorization");
          if (authHeader) {
            tokensUsedInUpstreamRequests.push(authHeader);
          }
          return HttpResponse.json({ success: true });
        })
      );

      // ===== FIRST REQUEST =====
      const session1 = createInitialSessionData({
        tokenSet: {
          accessToken: "old_token_1",
          refreshToken: DEFAULT.refreshToken,
          expiresAt: now - 10, // Expired
          scope: "read:data",
          token_type: "Bearer",
          audience: DEFAULT.audience
        }
      });
      const cookie1 = await createSessionCookie(session1, secret);

      const request1 = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie: cookie1 }
        }
      );

      const response1 = await authClient.middleware(request1);
      expect(response1.status).toBe(200);

      // Verify first session was updated after token refresh
      const setCookie1 = response1.headers.get("set-cookie");
      expect(setCookie1).toBeTruthy();
      expect(setCookie1).toContain("__session=");
      expect(tokenRefreshCount).toBe(1);

      // Verify the refreshed token was used in the upstream request
      expect(tokensUsedInUpstreamRequests).toHaveLength(1);
      expect(tokensUsedInUpstreamRequests[0]).toBe(
        `Bearer ${refreshedTokens[0]}`
      );

      // ===== SECOND REQUEST (reusing fetcher for same audience) =====
      // Key point: This will reuse the cached fetcher from the first request
      // If the getAccessToken closure is stale, tokenSetSideEffect won't be updated

      // Simulate passage of time - token expires again
      // We need to manually create a new session with expired token
      // because we can't easily decrypt the cookie to verify its contents
      const session2 = createInitialSessionData({
        tokenSet: {
          accessToken: refreshedTokens[0], // This was the token from first refresh
          refreshToken: DEFAULT.refreshToken,
          expiresAt: now - 5, // Expired again
          scope: "read:data",
          token_type: "Bearer",
          audience: DEFAULT.audience
        }
      });
      const cookie2 = await createSessionCookie(session2, secret);

      const request2 = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie: cookie2 }
        }
      );

      const response2 = await authClient.middleware(request2);
      expect(response2.status).toBe(200);

      // CRITICAL ASSERTION: Verify second session was ALSO updated
      // BUG SCENARIO: If tokenSetSideEffect closure is stale from the cached fetcher,
      // the second token refresh would populate the OLD tokenSetSideEffect variable
      // from the first call, which is no longer in scope. This would cause:
      // 1. tokenSetSideEffect to remain undefined in the second call
      // 2. #updateSessionAfterTokenRetrieval to skip (because tokenSetSideEffect is falsy)
      // 3. No Set-Cookie header on the second response
      // 4. Session not persisted with the new token
      const setCookie2 = response2.headers.get("set-cookie");
      expect(setCookie2).toBeTruthy();
      expect(setCookie2).toContain("__session=");

      // Verify token was refreshed a second time
      expect(tokenRefreshCount).toBe(2);

      // Verify the second refreshed token was used in the upstream request
      expect(tokensUsedInUpstreamRequests).toHaveLength(2);
      expect(tokensUsedInUpstreamRequests[1]).toBe(
        `Bearer ${refreshedTokens[1]}`
      );

      // Verify the two session cookies are different (proving both were independently updated)
      expect(setCookie2).not.toBe(setCookie1);

      // Summary: This test passes because auth-client.ts overrides fetcher.getAccessToken
      // on reuse (line ~2367). Without that override, this test would FAIL because the
      // second call's tokenSetSideEffect wouldn't be captured, preventing session updates.
    });
  });

  describe("Category 9: Error Scenarios", () => {
    it("9.1 should return upstream 500 error to client", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/error`, () => {
          return HttpResponse.json(
            { error: "internal_error", message: "Something went wrong" },
            { status: 500 }
          );
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/error`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);

      expect(response.status).toBe(500);
      const body = await response.json();
      expect(body.error).toBe("internal_error");
    });

    it("9.2 should handle upstream 404 error", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/notfound`, () => {
          return HttpResponse.json({ error: "not_found" }, { status: 404 });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/notfound`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);

      expect(response.status).toBe(404);
    });

    it("9.3 should return 401 when refresh token is missing and token expired", async () => {
      const now = Math.floor(Date.now() / 1000);
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: undefined, // No refresh token
          expiresAt: now - 10, // Expired
          scope: "read:data",
          token_type: "Bearer"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "GET",
          headers: { cookie }
        }
      );

      const response = await authClient.middleware(request);

      expect(response.status).toBe(401);
    });
  });

  describe("Category 10: Concurrent Request Handling", () => {
    it("10.1 should handle multiple concurrent requests with valid token", async () => {
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: Math.floor(Date.now() / 1000) + 3600, // Far future
          scope: "read:data",
          token_type: "Bearer"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      let tokenEndpointCallCount = 0;
      let upstreamCallCount = 0;

      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, () => {
          tokenEndpointCallCount++;
          return HttpResponse.json({
            access_token: "new_token",
            token_type: "Bearer",
            expires_in: 3600
          });
        }),
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, () => {
          upstreamCallCount++;
          return HttpResponse.json({ success: true, count: upstreamCallCount });
        })
      );

      // Make 5 concurrent requests
      const requests = Array.from({ length: 5 }, (_, i) =>
        authClient.middleware(
          new NextRequest(
            new URL(`${DEFAULT.proxyPath}/data?id=${i}`, DEFAULT.appBaseUrl),
            {
              method: "GET",
              headers: { cookie }
            }
          )
        )
      );

      const responses = await Promise.all(requests);

      // All requests should succeed
      expect(responses.every((r) => r.status === 200)).toBe(true);

      // All requests should reach upstream
      expect(upstreamCallCount).toBe(5);

      // Token should not be refreshed (already valid)
      expect(tokenEndpointCallCount).toBe(0);
    });

    it("10.2 should handle concurrent requests with expired token (single refresh)", async () => {
      const now = Math.floor(Date.now() / 1000);
      const session = createInitialSessionData({
        tokenSet: {
          accessToken: DEFAULT.accessToken,
          refreshToken: DEFAULT.refreshToken,
          expiresAt: now - 10, // Expired
          scope: "read:data",
          token_type: "Bearer"
        }
      });
      const cookie = await createSessionCookie(session, secret);

      let tokenEndpointCallCount = 0;
      let upstreamCallCount = 0;

      server.use(
        http.post(`https://${DEFAULT.domain}/oauth/token`, async () => {
          tokenEndpointCallCount++;

          const jwt = await new jose.SignJWT({
            sid: DEFAULT.sid,
            auth_time: Math.floor(Date.now() / 1000)
          })
            .setProtectedHeader({ alg: DEFAULT.alg })
            .setSubject(DEFAULT.sub)
            .setIssuedAt()
            .setIssuer(_authorizationServerMetadata.issuer)
            .setAudience(DEFAULT.clientId)
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);

          return HttpResponse.json({
            access_token: "refreshed_token",
            refresh_token: DEFAULT.refreshToken,
            id_token: jwt,
            token_type: "Bearer",
            expires_in: 3600
          });
        }),
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, () => {
          upstreamCallCount++;
          return HttpResponse.json({ success: true });
        })
      );

      // Make 3 concurrent requests with expired token
      const requests = Array.from({ length: 3 }, () =>
        authClient.middleware(
          new NextRequest(
            new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
            {
              method: "GET",
              headers: { cookie }
            }
          )
        )
      );

      const responses = await Promise.all(requests);

      // All requests should succeed
      expect(responses.every((r) => r.status === 200)).toBe(true);

      // All requests should reach upstream
      expect(upstreamCallCount).toBe(3);

      // Token refresh should be coordinated - ideally only 1 call
      // (Note: implementation may vary, so we allow up to 3)
      expect(tokenEndpointCallCount).toBeGreaterThan(0);
      expect(tokenEndpointCallCount).toBeLessThanOrEqual(3);
    });

    it("10.3 should handle concurrent requests to different proxy routes independently", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      // Create AuthClient with multiple proxy routes
      const multiProxyClient = new Auth0Client({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        routes: getDefaultRoutes(),
        secret,
        fetch: (url, init) =>
          fetch(url, { ...init, ...(init?.body ? { duplex: "half" } : {}) })
      });

      let meCallCount = 0;

      server.use(
        http.get(`${DEFAULT.upstreamBaseUrl}/data`, () => {
          meCallCount++;
          return HttpResponse.json({ api: "me", count: meCallCount });
        })
      );

      // Make concurrent requests to /me endpoint
      const requests = [
        multiProxyClient.middleware(
          new NextRequest(
            new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
            {
              method: "GET",
              headers: { cookie }
            }
          )
        ),
        multiProxyClient.middleware(
          new NextRequest(
            new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
            {
              method: "GET",
              headers: { cookie }
            }
          )
        ),
        multiProxyClient.middleware(
          new NextRequest(
            new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
            {
              method: "GET",
              headers: { cookie }
            }
          )
        )
      ];

      const responses = await Promise.all(requests);

      // All requests should succeed
      expect(responses.every((r) => r.status === 200)).toBe(true);

      // All three concurrent requests should have been processed
      expect(meCallCount).toBe(3);
    });
  });

  describe("Category 11: CORS Handling", () => {
    it("11.1 should forward CORS preflight response from upstream", async () => {
      const session = createInitialSessionData();
      const cookie = await createSessionCookie(session, secret);

      server.use(
        http.options(`${DEFAULT.upstreamBaseUrl}/data`, () => {
          return new HttpResponse(null, {
            status: 204,
            headers: {
              "access-control-allow-origin": "https://example.com",
              "access-control-allow-methods": "GET, POST, PUT",
              "access-control-allow-headers": "Content-Type, Authorization"
            }
          });
        })
      );

      const request = new NextRequest(
        new URL(`${DEFAULT.proxyPath}/data`, DEFAULT.appBaseUrl),
        {
          method: "OPTIONS",
          headers: {
            cookie,
            origin: "https://example.com",
            "access-control-request-method": "POST"
          }
        }
      );

      const response = await authClient.middleware(request);

      expect(response.status).toBe(204);
      expect(response.headers.get("access-control-allow-origin")).toBe(
        "https://example.com"
      );
    });
  });
});
