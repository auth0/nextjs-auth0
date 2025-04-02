/* eslint-disable @typescript-eslint/no-unused-vars */
import { NextRequest } from "next/server.js";
import * as oauth from "oauth4webapi";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { InvalidStateError, MissingStateError } from "../errors/index.js";
import { SessionData } from "../types/index.js";
import { AuthClient, AuthClientOptions } from "./auth-client.js";
import {
  ReadonlyRequestCookies,
  RequestCookies,
  ResponseCookies
} from "./cookies.js";
import {
  AbstractSessionStore,
  SessionStoreOptions
} from "./session/abstract-session-store.js";
import { TransactionStore } from "./transaction-store.js";

vi.mock("./transaction-store");
vi.mock("oauth4webapi");
vi.mock("jose");

const MockTransactionStore = TransactionStore;

class TestSessionStore extends AbstractSessionStore {
  constructor(config: SessionStoreOptions) {
    super(config);
  }
  async get(
    _reqCookies: RequestCookies | ReadonlyRequestCookies
  ): Promise<SessionData | null> {
    return null;
  }
  async set(
    _reqCookies: RequestCookies | ReadonlyRequestCookies,
    _resCookies: ResponseCookies,
    _session: SessionData,
    _isNew?: boolean | undefined
  ): Promise<void> {}
  async delete(
    _reqCookies: RequestCookies | ReadonlyRequestCookies,
    _resCookies: ResponseCookies
  ): Promise<void> {}
}

const baseOptions: Partial<AuthClientOptions> = {
  domain: "test.auth0.com",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  secret: "a-sufficiently-long-secret-for-testing",
  routes: {
    login: "/api/auth/login",
    logout: "/api/auth/logout",
    callback: "/api/auth/callback"
  }
};

describe("Ensure that redundant transaction cookies are deleted from auth-client methods", () => {
  let authClient: AuthClient;
  let mockTransactionStoreInstance: TransactionStore;
  let mockSessionStoreInstance: TestSessionStore;

  beforeEach(async () => {
    vi.clearAllMocks();

    mockTransactionStoreInstance = new MockTransactionStore({
      secret: "a-sufficiently-long-secret-for-testing"
    });
    const testSessionStoreOptions: SessionStoreOptions = {
      secret: "test-secret",
      cookieOptions: { name: "__session", path: "/", sameSite: "lax" }
    };
    mockSessionStoreInstance = new TestSessionStore(testSessionStoreOptions);

    mockTransactionStoreInstance.getCookiePrefix = vi
      .fn()
      .mockReturnValue("__txn_");
    mockTransactionStoreInstance.delete = vi.fn().mockResolvedValue(undefined);
    mockTransactionStoreInstance.deleteAll = vi
      .fn()
      .mockResolvedValue(undefined);
    mockTransactionStoreInstance.get = vi.fn().mockResolvedValue({
      payload: {
        state: "test-state",
        nonce: "test-nonce",
        codeVerifier: "cv",
        responseType: "code",
        returnTo: "/"
      }
    });

    mockSessionStoreInstance.get = vi.fn().mockResolvedValue({
      user: { sub: "user123" },
      internal: { sid: "sid123" },
      tokenSet: { idToken: "idtoken123" }
    });
    mockSessionStoreInstance.delete = vi.fn().mockResolvedValue(undefined);
    mockSessionStoreInstance.set = vi.fn().mockResolvedValue(undefined);

    authClient = new AuthClient({
      ...baseOptions,
      sessionStore: mockSessionStoreInstance as any,
      transactionStore: mockTransactionStoreInstance
    } as AuthClientOptions);

    (authClient as any).discoverAuthorizationServerMetadata = vi
      .fn()
      .mockResolvedValue([
        null,
        {
          issuer: "https://test.auth0.com/",
          authorization_endpoint: "https://test.auth0.com/authorize",
          token_endpoint: "https://test.auth0.com/oauth/token",
          jwks_uri: "https://test.auth0.com/.well-known/jwks.json",
          end_session_endpoint: "https://test.auth0.com/v2/logout" // Mock RP-Initiated Logout endpoint
        }
      ]);

    vi.spyOn(oauth, "validateAuthResponse").mockReturnValue(
      new URLSearchParams("code=auth_code")
    );
    vi.spyOn(oauth, "authorizationCodeGrantRequest").mockResolvedValue(
      new Response()
    );
    vi.spyOn(oauth, "processAuthorizationCodeResponse").mockResolvedValue({
      token_type: "Bearer",
      access_token: "access_token_123",
      id_token: "id_token_456",
      refresh_token: "refresh_token_789",
      expires_in: 3600,
      scope: "openid profile email"
    } as oauth.TokenEndpointResponse);

    const clientId = baseOptions.clientId ?? "test-client-id";
    vi.spyOn(oauth, "getValidatedIdTokenClaims").mockReturnValue({
      sub: "user123",
      sid: "sid123",
      nonce: "test-nonce",
      aud: clientId,
      iss: `https://${baseOptions.domain}/`,
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 3600
    });
  });

  describe("handleLogout", () => {
    it("should delete session cookie but no transaction cookies if none exist", async () => {
      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__session", "session-value");

      const res = await authClient.handleLogout(req);

      expect(mockSessionStoreInstance.delete).toHaveBeenCalledTimes(1);
      expect(mockTransactionStoreInstance.deleteAll).toHaveBeenCalledTimes(1);
      expect(mockTransactionStoreInstance.deleteAll).toHaveBeenCalledWith(
        req.cookies,
        res.cookies
      );

      expect(res.status).toBeGreaterThanOrEqual(300); // Accept 302 or 307
      expect(res.status).toBeLessThan(400);
    });

    it("should delete session cookie AND call deleteAll for transaction cookies", async () => {
      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__session", "session-value");
      req.cookies.set("__txn_state1", "txn-value1");
      req.cookies.set("__txn_state2", "txn-value2");
      req.cookies.set("other_cookie", "other-value");

      const res = await authClient.handleLogout(req);

      expect(mockSessionStoreInstance.delete).toHaveBeenCalledTimes(1);
      expect(mockTransactionStoreInstance.deleteAll).toHaveBeenCalledTimes(1);
      expect(mockTransactionStoreInstance.deleteAll).toHaveBeenCalledWith(
        req.cookies,
        res.cookies
      );

      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(res.status).toBeLessThan(400);
    });

    it("should call deleteAll for transaction cookies even if no session exists", async () => {
      mockSessionStoreInstance.get = vi.fn().mockResolvedValue(null);
      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__txn_state1", "txn-value1");

      const res = await authClient.handleLogout(req);

      expect(mockSessionStoreInstance.delete).toHaveBeenCalledTimes(1);
      expect(mockTransactionStoreInstance.deleteAll).toHaveBeenCalledTimes(1);
      expect(mockTransactionStoreInstance.deleteAll).toHaveBeenCalledWith(
        req.cookies,
        res.cookies
      );

      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(res.status).toBeLessThan(400);
    });

    it("should respect custom transaction cookie prefix when calling deleteAll", async () => {
      const customPrefix = "__my_txn_";
      mockTransactionStoreInstance.getCookiePrefix = vi
        .fn()
        .mockReturnValue(customPrefix);
      authClient = new AuthClient({
        ...baseOptions,
        sessionStore: mockSessionStoreInstance as any,
        transactionStore: mockTransactionStoreInstance
      } as AuthClientOptions);
      (authClient as any).discoverAuthorizationServerMetadata = vi
        .fn()
        .mockResolvedValue([null, { end_session_endpoint: "http://..." }]);

      const req = new NextRequest("http://localhost:3000/api/auth/logout");
      req.cookies.set("__session", "session-value");
      req.cookies.set(`${customPrefix}state1`, "txn-value1");
      req.cookies.set("__txn_state2", "default-prefix-value");

      const res = await authClient.handleLogout(req);

      expect(mockSessionStoreInstance.delete).toHaveBeenCalledTimes(1);
      expect(mockTransactionStoreInstance.deleteAll).toHaveBeenCalledTimes(1);
      expect(mockTransactionStoreInstance.deleteAll).toHaveBeenCalledWith(
        req.cookies,
        res.cookies
      );

      expect(res.status).toBeGreaterThanOrEqual(300);
      expect(res.status).toBeLessThan(400);
    });
  });

  describe("handleCallback", () => {
    it("should delete the correct transaction cookie on success", async () => {
      const state = "test-state";
      const req = new NextRequest(
        `http://localhost:3000/api/auth/callback?code=auth_code&state=${state}`
      );

      const res = await authClient.handleCallback(req);

      expect(mockTransactionStoreInstance.get).toHaveBeenCalledWith(
        req.cookies,
        state
      );
      expect(mockTransactionStoreInstance.delete).toHaveBeenCalledTimes(1);
      expect(mockTransactionStoreInstance.delete).toHaveBeenCalledWith(
        res.cookies,
        state
      );
      expect(mockSessionStoreInstance.set).toHaveBeenCalledTimes(1);
      expect(res.status).toBeGreaterThanOrEqual(300); // Accept redirects
      expect(res.status).toBeLessThan(400);
      expect(res.headers.get("location")).toBe("http://localhost:3000/");
    });

    it("should NOT delete transaction cookie on InvalidStateError", async () => {
      const state = "invalid-state";
      mockTransactionStoreInstance.get = vi.fn().mockResolvedValue(null);
      const req = new NextRequest(
        `http://localhost:3000/api/auth/callback?code=auth_code&state=${state}`
      );

      const res = await authClient.handleCallback(req);

      expect(mockTransactionStoreInstance.get).toHaveBeenCalledWith(
        req.cookies,
        state
      );
      expect(mockTransactionStoreInstance.delete).not.toHaveBeenCalled();
      expect(mockSessionStoreInstance.set).not.toHaveBeenCalled();
      expect(res.status).toBe(500);
      const body = await res.text();
      expect(body).toContain(new InvalidStateError().message);
    });

    it("should NOT delete transaction cookie on MissingStateError", async () => {
      const req = new NextRequest(
        `http://localhost:3000/api/auth/callback?code=auth_code`
      );

      const res = await authClient.handleCallback(req);

      expect(mockTransactionStoreInstance.get).not.toHaveBeenCalled();
      expect(mockTransactionStoreInstance.delete).not.toHaveBeenCalled();
      expect(mockSessionStoreInstance.set).not.toHaveBeenCalled();
      expect(res.status).toBe(500);
      const body = await res.text();
      expect(body).toContain(new MissingStateError().message);
    });
  });
});
