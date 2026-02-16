import { NextRequest, NextResponse } from "next/server.js";
import * as jose from "jose";
import * as oauth from "oauth4webapi";
import { describe, expect, it, vi } from "vitest";

import { getDefaultRoutes } from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { RESPONSE_TYPES, SessionData } from "../types/index.js";
import { createAuthCompletePostMessageResponse } from "../utils/html-helpers.js";
import { AuthClient } from "./auth-client.js";
import { decrypt, encrypt } from "./cookies.js";
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

describe("MFA Popup (returnStrategy + postMessage)", async () => {
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
    keyPair: await jose.generateKeyPair("RS256")
  };

  const _authorizationServerMetadata: oauth.AuthorizationServer = {
    issuer: `https://${DEFAULT.domain}/`,
    authorization_endpoint: `https://${DEFAULT.domain}/authorize`,
    token_endpoint: `https://${DEFAULT.domain}/oauth/token`,
    jwks_uri: `https://${DEFAULT.domain}/.well-known/jwks.json`,
    end_session_endpoint: `https://${DEFAULT.domain}/v2/logout`
  };

  function getMockAuthorizationServer({
    tokenEndpointResponse,
    tokenEndpointErrorResponse,
    nonce,
    keyPair = DEFAULT.keyPair
  }: {
    tokenEndpointResponse?: oauth.TokenEndpointResponse | oauth.OAuth2Error;
    tokenEndpointErrorResponse?: oauth.OAuth2Error;
    nonce?: string;
    keyPair?: jose.GenerateKeyPairResult;
  } = {}) {
    return vi.fn(
      async (
        input: RequestInfo | URL,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        _init?: RequestInit
      ): Promise<Response> => {
        let url: URL;
        if (input instanceof Request) {
          url = new URL(input.url);
        } else {
          url = new URL(input);
        }

        if (url.pathname === "/oauth/token") {
          const jwt = await new jose.SignJWT({
            sid: DEFAULT.sid,
            auth_time: Date.now(),
            nonce: nonce ?? "nonce-value",
            email: "user@example.com"
          })
            .setProtectedHeader({ alg: DEFAULT.alg })
            .setSubject(DEFAULT.sub)
            .setIssuedAt()
            .setIssuer(_authorizationServerMetadata.issuer)
            .setAudience(DEFAULT.clientId)
            .setExpirationTime("2h")
            .sign(keyPair.privateKey);

          if (tokenEndpointErrorResponse) {
            return Response.json(tokenEndpointErrorResponse, { status: 400 });
          }
          return Response.json(
            tokenEndpointResponse ?? {
              token_type: "Bearer",
              access_token: DEFAULT.accessToken,
              refresh_token: DEFAULT.refreshToken,
              id_token: jwt,
              expires_in: 86400,
              scope: "openid profile email"
            }
          );
        }
        if (url.pathname === "/.well-known/openid-configuration") {
          return Response.json(_authorizationServerMetadata);
        }

        return new Response(null, { status: 404 });
      }
    );
  }

  async function getCachedJWKS(): Promise<jose.ExportedJWKSCache> {
    const publicJwk = await jose.exportJWK(DEFAULT.keyPair.publicKey);
    return {
      jwks: { keys: [publicJwk] },
      uat: Date.now() - 1000 * 60
    };
  }

  // ──────────────────────────────────────────────────────────────
  //  handleLogin + returnStrategy
  // ──────────────────────────────────────────────────────────────
  describe("handleLogin — returnStrategy", () => {
    it("should parse returnStrategy=postMessage from URL and store in transaction", async () => {
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

      const url = new URL("/auth/login", DEFAULT.appBaseUrl);
      url.searchParams.set("returnStrategy", "postMessage");
      url.searchParams.set("audience", "https://api.example.com");
      url.searchParams.set("prompt", "login");
      const request = new NextRequest(url, { method: "GET" });

      const response = await authClient.handleLogin(request);
      expect(response.status).toEqual(307);

      // Verify returnStrategy NOT forwarded to Auth0
      const authUrl = new URL(response.headers.get("Location")!);
      expect(authUrl.searchParams.has("returnStrategy")).toBe(false);
      expect(authUrl.searchParams.get("audience")).toBe(
        "https://api.example.com"
      );
      expect(authUrl.searchParams.get("prompt")).toBe("login");

      // Verify transaction state contains returnStrategy
      const state = authUrl.searchParams.get("state")!;
      const transactionCookie = response.cookies.get(`__txn_${state}`);
      expect(transactionCookie).toBeDefined();
      const { payload: txn } = (await decrypt(
        transactionCookie!.value,
        secret
      )) as jose.JWTDecryptResult;
      expect(txn.returnStrategy).toBe("postMessage");
    });

    it("should accept returnStrategy=redirect (no-op, default)", async () => {
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

      const url = new URL("/auth/login", DEFAULT.appBaseUrl);
      url.searchParams.set("returnStrategy", "redirect");
      const request = new NextRequest(url, { method: "GET" });

      const response = await authClient.handleLogin(request);
      expect(response.status).toEqual(307);

      // returnStrategy=redirect → not stored in transaction (default)
      const authUrl = new URL(response.headers.get("Location")!);
      const state = authUrl.searchParams.get("state")!;
      const transactionCookie = response.cookies.get(`__txn_${state}`);
      const { payload: txn } = (await decrypt(
        transactionCookie!.value,
        secret
      )) as jose.JWTDecryptResult;
      // When returnStrategy is 'redirect' (default), it's not stored to minimize cookie size
      expect(txn.returnStrategy).toBeUndefined();
    });

    it("should return 400 for invalid returnStrategy", async () => {
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

      const url = new URL("/auth/login", DEFAULT.appBaseUrl);
      url.searchParams.set("returnStrategy", "invalid_value");
      const request = new NextRequest(url, { method: "GET" });

      const response = await authClient.handleLogin(request);
      expect(response.status).toEqual(400);
      const text = await response.text();
      expect(text).toContain("Invalid returnStrategy");
    });

    it("should store audience and scope in transaction for postMessage flow", async () => {
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

      const url = new URL("/auth/login", DEFAULT.appBaseUrl);
      url.searchParams.set("returnStrategy", "postMessage");
      url.searchParams.set("audience", "https://api.example.com");
      url.searchParams.set("scope", "openid profile email read:data");
      const request = new NextRequest(url, { method: "GET" });

      const response = await authClient.handleLogin(request);
      const authUrl = new URL(response.headers.get("Location")!);
      const state = authUrl.searchParams.get("state")!;
      const transactionCookie = response.cookies.get(`__txn_${state}`);
      const { payload: txn } = (await decrypt(
        transactionCookie!.value,
        secret
      )) as jose.JWTDecryptResult;

      expect(txn.audience).toBe("https://api.example.com");
      expect(txn.scope).toBe("openid profile email read:data");
      expect(txn.returnStrategy).toBe("postMessage");
    });
  });

  // ──────────────────────────────────────────────────────────────
  //  startInteractiveLogin — returnStrategy validation
  // ──────────────────────────────────────────────────────────────
  describe("startInteractiveLogin — returnStrategy", () => {
    it("should throw InvalidConfigurationError for invalid returnStrategy (programmatic)", async () => {
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

      await expect(
        authClient.startInteractiveLogin({
          returnStrategy: "bogus" as any
        })
      ).rejects.toThrow(/Invalid returnStrategy/);
    });

    it("should accept returnStrategy=postMessage (programmatic)", async () => {
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

      const response = await authClient.startInteractiveLogin({
        returnStrategy: "postMessage",
        authorizationParameters: {
          audience: "https://api.example.com"
        }
      });

      expect(response.status).toEqual(307);
    });
  });

  // ──────────────────────────────────────────────────────────────
  //  handleCallback — postMessage branch
  // ──────────────────────────────────────────────────────────────
  describe("handleCallback — postMessage branch", () => {
    it("should return HTML with postMessage on returnStrategy=postMessage", async () => {
      const state = "txn-state";
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const jwksCache = await getCachedJWKS();
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
        jwksCache
      });

      // Pre-populate session (popup flows MERGE into existing session)
      const existingSession = createSessionData({
        tokenSet: {
          accessToken: "original-at",
          refreshToken: "original-rt",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        }
      });
      const sessionExp = Math.floor(Date.now() / 1000 + 86400);
      const sessionCookieVal = await encrypt(
        existingSession,
        secret,
        sessionExp
      );

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/",
        returnStrategy: "postMessage",
        audience: "https://api.example.com",
        scope: "openid profile email"
      };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      const headers = new Headers();
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}; __session=${sessionCookieVal}`
      );
      const request = new NextRequest(url, { method: "GET", headers });

      const response = await authClient.handleCallback(request);

      // Should return 200 HTML, NOT a 307 redirect
      expect(response.status).toEqual(200);
      expect(response.headers.get("Content-Type")).toBe(
        "text/html; charset=utf-8"
      );
      expect(response.headers.get("Cache-Control")).toContain("no-store");

      const body = await response.text();
      expect(body).toContain("<!DOCTYPE html>");
      expect(body).toContain("window.opener.postMessage");
      expect(body).toContain("auth_complete");
      expect(body).toContain("window.close()");
      expect(body).toContain("2000"); // auto-close delay

      // Should contain user info
      expect(body).toContain(DEFAULT.sub);

      // Transaction cookie should be deleted
      const txnCookie = response.cookies.get(`__txn_${state}`);
      expect(txnCookie).toBeDefined();
      expect(txnCookie!.value).toEqual("");
      expect(txnCookie!.maxAge).toEqual(0);

      // Session cookie should be set (merged session)
      const sessionCookie = response.cookies.get("__session");
      expect(sessionCookie).toBeDefined();
    });

    it("should return redirect for default returnStrategy (redirect)", async () => {
      const state = "txn-state";
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const jwksCache = await getCachedJWKS();
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
        jwksCache
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/dashboard"
        // No returnStrategy → default 'redirect'
      };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      const headers = new Headers();
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, { method: "GET", headers });

      const response = await authClient.handleCallback(request);

      // Standard flow: should redirect
      expect(response.status).toEqual(307);
      expect(response.headers.get("Location")).toContain("/dashboard");
    });

    it("should include CSP nonce in script tag when cspNonce is configured", async () => {
      const state = "txn-state";
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const jwksCache = await getCachedJWKS();
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
        jwksCache,
        cspNonce: "abc123XYZ"
      });

      // Pre-populate session
      const existingSession = createSessionData({});
      const sessionExp = Math.floor(Date.now() / 1000 + 86400);
      const sessionCookieVal = await encrypt(
        existingSession,
        secret,
        sessionExp
      );

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/",
        returnStrategy: "postMessage"
      };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      const headers = new Headers();
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}; __session=${sessionCookieVal}`
      );
      const request = new NextRequest(url, { method: "GET", headers });

      const response = await authClient.handleCallback(request);
      expect(response.status).toEqual(200);

      const body = await response.text();
      expect(body).toContain('nonce="abc123XYZ"');
    });

    it("should NOT include nonce attribute when cspNonce is not configured", async () => {
      const state = "txn-state";
      const code = "auth-code";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const jwksCache = await getCachedJWKS();
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
        jwksCache
        // No cspNonce
      });

      const existingSession = createSessionData({});
      const sessionExp = Math.floor(Date.now() / 1000 + 86400);
      const sessionCookieVal = await encrypt(
        existingSession,
        secret,
        sessionExp
      );

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/",
        returnStrategy: "postMessage"
      };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      const headers = new Headers();
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}; __session=${sessionCookieVal}`
      );
      const request = new NextRequest(url, { method: "GET", headers });

      const response = await authClient.handleCallback(request);
      const body = await response.text();
      expect(body).not.toContain("nonce=");
    });
  });

  // ──────────────────────────────────────────────────────────────
  //  handleCallbackError — postMessage error branch
  // ──────────────────────────────────────────────────────────────
  describe("handleCallbackError — postMessage error", () => {
    it("should return error HTML when returnStrategy=postMessage and OAuth error occurs", async () => {
      const state = "txn-state";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const jwksCache = await getCachedJWKS();
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
        jwksCache
      });

      // Create a callback URL with an OAuth error (access_denied)
      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("error", "access_denied");
      url.searchParams.set("error_description", "User denied access");
      url.searchParams.set("state", state);

      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/",
        returnStrategy: "postMessage"
      };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      const headers = new Headers();
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, { method: "GET", headers });

      const response = await authClient.handleCallback(request);

      // Should return 200 HTML with error postMessage (NOT a redirect)
      expect(response.status).toEqual(200);
      expect(response.headers.get("Content-Type")).toBe(
        "text/html; charset=utf-8"
      );

      const body = await response.text();
      expect(body).toContain("auth_complete");
      expect(body).toContain("false"); // success: false
      expect(body).toContain("window.opener.postMessage");

      // Transaction cookie should be cleaned up
      const txnCookie = response.cookies.get(`__txn_${state}`);
      expect(txnCookie).toBeDefined();
      expect(txnCookie!.value).toEqual("");
      expect(txnCookie!.maxAge).toEqual(0);
    });

    it("should return redirect error for standard flow (no returnStrategy)", async () => {
      const state = "txn-state";

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const jwksCache = await getCachedJWKS();
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
        jwksCache
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("error", "access_denied");
      url.searchParams.set("error_description", "User denied");
      url.searchParams.set("state", state);

      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/"
        // No returnStrategy → default 'redirect'
      };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      const headers = new Headers();
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, { method: "GET", headers });

      const response = await authClient.handleCallback(request);

      // Standard error flow: default onCallback returns error (not HTML postMessage)
      // The key assertion is that it does NOT return postMessage HTML
      const contentType = response.headers.get("Content-Type") || "";
      expect(contentType).not.toContain("text/html");
      // Should not contain postMessage script
      const body = await response.text();
      expect(body).not.toContain("window.opener.postMessage");
    });
  });

  // ──────────────────────────────────────────────────────────────
  //  createAuthCompletePostMessageResponse
  // ──────────────────────────────────────────────────────────────
  describe("createAuthCompletePostMessageResponse", () => {
    it("should generate success HTML with user data", async () => {
      const response = createAuthCompletePostMessageResponse({
        success: true,
        user: { sub: "auth0|123", email: "user@example.com" }
      });

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe(
        "text/html; charset=utf-8"
      );
      expect(response.headers.get("Cache-Control")).toBe("no-store");

      const body = await response.text();
      expect(body).toContain("auth_complete");
      expect(body).toContain("auth0|123");
      expect(body).toContain("user@example.com");
      expect(body).toContain("window.opener.postMessage");
      expect(body).toContain("window.close()");
      expect(body).toContain("2000");
    });

    it("should generate error HTML", async () => {
      const response = createAuthCompletePostMessageResponse({
        success: false,
        error: { code: "access_denied", message: "User denied" }
      });

      const body = await response.text();
      expect(body).toContain("auth_complete");
      expect(body).toContain("access_denied");
      expect(body).toContain("Authentication failed");
    });

    it("should include nonce attribute when nonce is provided", async () => {
      const response = createAuthCompletePostMessageResponse({
        success: true,
        nonce: "myNonce123"
      });

      const body = await response.text();
      expect(body).toContain('nonce="myNonce123"');
    });

    it("should NOT include nonce attribute when nonce is not provided", async () => {
      const response = createAuthCompletePostMessageResponse({
        success: true
      });

      const body = await response.text();
      expect(body).not.toContain("nonce=");
    });

    it("should reject invalid CSP nonce characters", async () => {
      expect(() =>
        createAuthCompletePostMessageResponse({
          success: true,
          nonce: 'abc"><script>alert(1)</script>'
        })
      ).toThrow(/cspNonce must contain only base64 characters/);
    });

    it("should escape < in JSON to prevent script injection (XSS)", async () => {
      const response = createAuthCompletePostMessageResponse({
        success: false,
        error: {
          code: "xss_test",
          message: '</script><script>alert("xss")</script>'
        }
      });

      const body = await response.text();
      // The JSON inside <script> should have < escaped as \u003c
      // to prevent </script> injection
      expect(body).not.toContain("</script><script>");
      expect(body).toContain("\\u003c");
    });

    it("should HTML-escape error messages in <p> tag", async () => {
      const response = createAuthCompletePostMessageResponse({
        success: false,
        error: {
          code: "test",
          message: '<img src=x onerror="alert(1)">'
        }
      });

      const body = await response.text();
      // The <p> tag should have HTML entities, not raw HTML
      expect(body).not.toContain('<img src=x onerror="alert(1)">');
    });
  });

  // ──────────────────────────────────────────────────────────────
  //  handleAccessToken — mergeScopes
  // ──────────────────────────────────────────────────────────────
  describe("handleAccessToken — mergeScopes", () => {
    it("should pass mergeScopes=false to getTokenSet when query param is 'false'", async () => {
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
        fetch: getMockAuthorizationServer(),
        enableAccessTokenEndpoint: true
      });

      // Create a session with a matching MRRT token
      const session = createSessionData({
        tokenSet: {
          accessToken: "at-primary",
          refreshToken: "rt-primary",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        accessTokens: [
          {
            accessToken: "at-for-api",
            audience: "https://api.example.com",
            scope: "openid profile email",
            requestedScope: "read:data",
            expiresAt: Math.floor(Date.now() / 1000) + 3600
          }
        ]
      });

      const sessionExp = Math.floor(Date.now() / 1000 + 86400);
      const sessionCookieVal = await encrypt(session, secret, sessionExp);

      const url = new URL("/auth/access-token", DEFAULT.appBaseUrl);
      url.searchParams.set("audience", "https://api.example.com");
      url.searchParams.set("scope", "read:data");
      url.searchParams.set("mergeScopes", "false");

      const headers = new Headers();
      headers.set("cookie", `__session=${sessionCookieVal}`);
      const request = new NextRequest(url, { method: "GET", headers });

      const response = await authClient.handleAccessToken(request);

      // When mergeScopes=false, scope lookup should match the accessToken's
      // requestedScope exactly ("read:data"), not merge with global scopes
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.token).toBe("at-for-api");
    });

    it("should use default mergeScopes behavior when param is absent", async () => {
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
        fetch: getMockAuthorizationServer(),
        enableAccessTokenEndpoint: true
      });

      const session = createSessionData({
        tokenSet: {
          accessToken: "at-primary",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        }
      });

      const sessionExp = Math.floor(Date.now() / 1000 + 86400);
      const sessionCookieVal = await encrypt(session, secret, sessionExp);

      const url = new URL("/auth/access-token", DEFAULT.appBaseUrl);
      // No mergeScopes param

      const headers = new Headers();
      headers.set("cookie", `__session=${sessionCookieVal}`);
      const request = new NextRequest(url, { method: "GET", headers });

      const response = await authClient.handleAccessToken(request);
      // Default behavior — should work (mergeScopes defaults to true/undefined)
      expect(response.status).toBe(200);
    });
  });

  // ──────────────────────────────────────────────────────────────
  //  getTokenSet — mergeScopes isolation
  // ──────────────────────────────────────────────────────────────
  describe("getTokenSet — mergeScopes", () => {
    it("should use ONLY options.scope when mergeScopes=false", async () => {
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

      // Session with MRRT token cached for specific scope
      const session = createSessionData({
        tokenSet: {
          accessToken: "at-primary",
          refreshToken: "rt-primary",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        },
        accessTokens: [
          {
            accessToken: "at-popup",
            audience: "https://api.example.com",
            scope: "openid profile email",
            requestedScope: "read:data",
            expiresAt: Math.floor(Date.now() / 1000) + 3600
          }
        ]
      });

      const [error, result] = await authClient.getTokenSet(session, {
        audience: "https://api.example.com",
        scope: "read:data",
        mergeScopes: false
      });

      expect(error).toBeNull();
      expect(result).toBeDefined();
      expect(result!.tokenSet.accessToken).toBe("at-popup");
    });

    it("should use empty string when mergeScopes=false and no scope provided", async () => {
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

      const session = createSessionData({
        tokenSet: {
          accessToken: "at-primary",
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        }
      });

      // mergeScopes=false with no scope → empty string scope lookup
      const [error] = await authClient.getTokenSet(session, {
        audience: "https://api.example.com",
        mergeScopes: false
      });

      // Should return error (no token matches empty scope + non-default audience)
      // because there's no matching MRRT token and no refresh token
      expect(error).toBeDefined();
    });
  });

  // ──────────────────────────────────────────────────────────────
  //  cspNonce global config
  // ──────────────────────────────────────────────────────────────
  describe("cspNonce global config", () => {
    it("should store cspNonce from constructor options", async () => {
      // Test that the nonce is used in postMessage response
      const response = createAuthCompletePostMessageResponse({
        success: true,
        nonce: "testNonce123"
      });
      const body = await response.text();
      expect(body).toContain('nonce="testNonce123"');
    });
  });

  // ──────────────────────────────────────────────────────────────
  //  OnCallbackContext — returnStrategy exposure
  // ──────────────────────────────────────────────────────────────
  describe("OnCallbackContext — returnStrategy", () => {
    it("should include returnStrategy in onCallback context for postMessage flows", async () => {
      const state = "txn-state";
      const code = "auth-code";
      let capturedCtx: any;

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const jwksCache = await getCachedJWKS();
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
        jwksCache,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        onCallback: async (_error, ctx, _session) => {
          capturedCtx = ctx;
          return NextResponse.redirect(
            new URL(ctx.returnTo || "/", DEFAULT.appBaseUrl)
          );
        }
      });

      // Pre-populate session
      const existingSession = createSessionData({});
      const sessionExp = Math.floor(Date.now() / 1000 + 86400);
      const sessionCookieVal = await encrypt(
        existingSession,
        secret,
        sessionExp
      );

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/",
        returnStrategy: "postMessage"
      };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      const headers = new Headers();
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}; __session=${sessionCookieVal}`
      );
      const request = new NextRequest(url, { method: "GET", headers });

      await authClient.handleCallback(request);

      expect(capturedCtx).toBeDefined();
      expect(capturedCtx.returnStrategy).toBe("postMessage");
    });

    it("should include returnStrategy=redirect in context for standard flows", async () => {
      const state = "txn-state";
      const code = "auth-code";
      let capturedCtx: any;

      const secret = await generateSecret(32);
      const transactionStore = new TransactionStore({ secret });
      const sessionStore = new StatelessSessionStore({ secret });
      const jwksCache = await getCachedJWKS();
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
        jwksCache,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        onCallback: async (_error, ctx, _session) => {
          capturedCtx = ctx;
          return NextResponse.redirect(
            new URL(ctx.returnTo || "/", DEFAULT.appBaseUrl)
          );
        }
      });

      const url = new URL("/auth/callback", DEFAULT.appBaseUrl);
      url.searchParams.set("code", code);
      url.searchParams.set("state", state);

      const transactionState: TransactionState = {
        nonce: "nonce-value",
        maxAge: 3600,
        codeVerifier: "code-verifier",
        responseType: RESPONSE_TYPES.CODE,
        state: state,
        returnTo: "/dashboard"
        // No returnStrategy
      };
      const maxAge = 60 * 60;
      const expiration = Math.floor(Date.now() / 1000 + maxAge);

      const headers = new Headers();
      headers.set(
        "cookie",
        `__txn_${state}=${await encrypt(transactionState, secret, expiration)}`
      );
      const request = new NextRequest(url, { method: "GET", headers });

      await authClient.handleCallback(request);

      expect(capturedCtx).toBeDefined();
      expect(capturedCtx.returnStrategy).toBe("redirect");
    });
  });
});
