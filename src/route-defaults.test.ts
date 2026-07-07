import { NextRequest, NextResponse } from "next/server.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthClient } from "./server/auth-client.js";
import { Auth0Client } from "./server/client.js";
import { StatelessSessionStore } from "./server/session/stateless-session-store.js";
import { TransactionStore } from "./server/transaction-store.js";
import { getDefaultRoutes } from "./test/defaults.js";
import { generateSecret } from "./test/utils.js";

vi.mock("next/headers.js", async () => {
  const { createNextHeadersMock } = await import("./test/mocks.js");
  return createNextHeadersMock();
});

const TEST_ENV_VARS = {
  AUTH0_DOMAIN: "test.auth0.com",
  AUTH0_CLIENT_ID: "test_client",
  AUTH0_CLIENT_SECRET: "test_secret",
  AUTH0_SECRET: "a".repeat(32),
  APP_BASE_URL: "https://example.com"
};

function makeReq(method: string, path: string) {
  return new NextRequest(`https://example.com${path}`, { method });
}

describe("Route defaults", () => {
  beforeEach(() => {
    Object.entries(TEST_ENV_VARS).forEach(([key, value]) => {
      process.env[key] = value;
    });
  });

  afterEach(() => {
    Object.keys(TEST_ENV_VARS).forEach((key) => {
      delete process.env[key];
    });
  });

  describe("Part 1: Default route paths (Auth0Client)", () => {
    it("should have correct default route paths", () => {
      const client = new Auth0Client();
      const routes = (client as any).routes;

      expect(routes.login).toBe("/auth/login");
      expect(routes.logout).toBe("/auth/logout");
      expect(routes.callback).toBe("/auth/callback");
      expect(routes.backChannelLogout).toBe("/auth/backchannel-logout");
      expect(routes.profile).toBe("/auth/profile");
      expect(routes.accessToken).toBe("/auth/access-token");
      expect(routes.connectAccount).toBe("/auth/connect");
      expect(routes.mfaAuthenticators).toBe("/auth/mfa/authenticators");
      expect(routes.mfaChallenge).toBe("/auth/mfa/challenge");
      expect(routes.mfaVerify).toBe("/auth/mfa/verify");
      expect(routes.mfaAssociate).toBe("/auth/mfa/associate");
      expect(routes.passwordlessStart).toBe("/auth/passwordless/start");
      expect(routes.passwordlessVerify).toBe("/auth/passwordless/verify");
      expect(routes.passwordlessDbOtpChallenge).toBe(
        "/auth/passwordless/otp/challenge"
      );
      expect(routes.passwordlessDbGetToken).toBe(
        "/auth/passwordless/otp/token"
      );
      expect(routes.passkeyRegister).toBe("/auth/passkey/register");
      expect(routes.passkeyChallenge).toBe("/auth/passkey/challenge");
      expect(routes.passkeyGetToken).toBe("/auth/passkey/get-token");
      expect(routes.passkeyEnrollmentChallenge).toBe(
        "/auth/passkey/enrollment-challenge"
      );
      expect(routes.passkeyEnrollmentVerify).toBe(
        "/auth/passkey/enrollment-verify"
      );
    });
  });

  describe("Part 2: Handler dispatch (HTTP method + path → handler)", () => {
    let secret: string;
    let authClient: AuthClient;

    beforeEach(async () => {
      secret = await generateSecret(32);
      authClient = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore: new StatelessSessionStore({ secret }),
        domain: "test.auth0.com",
        clientId: "client_id",
        clientSecret: "client_secret",
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes(),
        fetch: vi.fn().mockResolvedValue(new Response())
      });
    });

    it("GET /auth/login should call handleLogin", async () => {
      const spy = vi
        .spyOn(authClient, "handleLogin")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("GET", "/auth/login"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("GET /auth/logout should call handleLogout", async () => {
      const spy = vi
        .spyOn(authClient, "handleLogout")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("GET", "/auth/logout"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("GET /auth/callback should call handleCallback", async () => {
      const spy = vi
        .spyOn(authClient, "handleCallback")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("GET", "/auth/callback"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("GET /auth/profile should call handleProfile", async () => {
      const spy = vi
        .spyOn(authClient, "handleProfile")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("GET", "/auth/profile"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/backchannel-logout should call handleBackChannelLogout", async () => {
      const spy = vi
        .spyOn(authClient, "handleBackChannelLogout")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/backchannel-logout"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("GET /auth/mfa/authenticators should call handleGetAuthenticators", async () => {
      const spy = vi
        .spyOn(authClient, "handleGetAuthenticators")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("GET", "/auth/mfa/authenticators"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/mfa/challenge should call handleChallenge", async () => {
      const spy = vi
        .spyOn(authClient, "handleChallenge")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/mfa/challenge"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/mfa/verify should call handleVerify", async () => {
      const spy = vi
        .spyOn(authClient, "handleVerify")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/mfa/verify"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/mfa/associate should call handleAssociate", async () => {
      const spy = vi
        .spyOn(authClient, "handleAssociate")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/mfa/associate"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/passwordless/start should call handlePasswordlessStart", async () => {
      const spy = vi
        .spyOn(authClient, "handlePasswordlessStart")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/passwordless/start"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/passwordless/verify should call handlePasswordlessVerify", async () => {
      const spy = vi
        .spyOn(authClient, "handlePasswordlessVerify")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/passwordless/verify"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/passwordless/otp/challenge should call handlePasswordlessDbOtpChallenge", async () => {
      const spy = vi
        .spyOn(authClient, "handlePasswordlessDbOtpChallenge")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(
        makeReq("POST", "/auth/passwordless/otp/challenge")
      );

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/passwordless/otp/token should call handlePasswordlessDbGetToken", async () => {
      const spy = vi
        .spyOn(authClient, "handlePasswordlessDbGetToken")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/passwordless/otp/token"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/passkey/register should call handlePasskeyRegister", async () => {
      const spy = vi
        .spyOn(authClient, "handlePasskeyRegister")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/passkey/register"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/passkey/challenge should call handlePasskeyChallenge", async () => {
      const spy = vi
        .spyOn(authClient, "handlePasskeyChallenge")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/passkey/challenge"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/passkey/get-token should call handlePasskeyGetToken", async () => {
      const spy = vi
        .spyOn(authClient, "handlePasskeyGetToken")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/passkey/get-token"));

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/passkey/enrollment-challenge should call handlePasskeyEnrollmentChallenge", async () => {
      const spy = vi
        .spyOn(authClient, "handlePasskeyEnrollmentChallenge")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(
        makeReq("POST", "/auth/passkey/enrollment-challenge")
      );

      expect(spy).toHaveBeenCalledOnce();
    });

    it("POST /auth/passkey/enrollment-verify should call handlePasskeyEnrollmentVerify", async () => {
      const spy = vi
        .spyOn(authClient, "handlePasskeyEnrollmentVerify")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(
        makeReq("POST", "/auth/passkey/enrollment-verify")
      );

      expect(spy).toHaveBeenCalledOnce();
    });
  });

  describe("Part 3: Wrong method and unknown routes", () => {
    let secret: string;
    let authClient: AuthClient;

    beforeEach(async () => {
      secret = await generateSecret(32);
      authClient = new AuthClient({
        transactionStore: new TransactionStore({ secret }),
        sessionStore: new StatelessSessionStore({ secret }),
        domain: "test.auth0.com",
        clientId: "client_id",
        clientSecret: "client_secret",
        secret,
        appBaseUrl: "https://example.com",
        routes: getDefaultRoutes(),
        fetch: vi.fn().mockResolvedValue(new Response())
      });
    });

    it("GET /auth/unknown-route should return NextResponse.next()", async () => {
      const res = await authClient.handler(
        makeReq("GET", "/auth/unknown-route")
      );

      expect(res.status).toBe(200);
    });

    it("POST /auth/login (wrong method) should not call handleLogin", async () => {
      const spy = vi
        .spyOn(authClient, "handleLogin")
        .mockResolvedValue(NextResponse.next());

      await authClient.handler(makeReq("POST", "/auth/login"));

      expect(spy).not.toHaveBeenCalled();
    });
  });
});
