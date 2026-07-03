import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { beforeEach, describe, expect, it } from "vitest";

import {
  createAuthorizationServerMetadata,
  getDefaultRoutes,
  setupMswLifecycle
} from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  email: "user@example.com",
  phoneNumber: "+14155550100",
  otp: "123456",
  authSession: "opaque-auth-session-token",
  connection: "my-db-connection",
  accessToken: "test-access-token"
};

const CHALLENGE_URL = `https://${DEFAULT.domain}/otp/challenge`;
const TOKEN_URL = `https://${DEFAULT.domain}/oauth/token`;

const server = setupServer(
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () => {
    return HttpResponse.json(createAuthorizationServerMetadata(DEFAULT.domain));
  })
);

setupMswLifecycle(server);

describe("AuthClient passwordless DB methods", () => {
  let secret: string;
  let authClient: AuthClient;

  beforeEach(async () => {
    secret = await generateSecret(32);
    const transactionStore = new TransactionStore({ secret });
    const sessionStore = new StatelessSessionStore({ secret });
    authClient = new AuthClient({
      domain: DEFAULT.domain,
      clientId: DEFAULT.clientId,
      clientSecret: DEFAULT.clientSecret,
      appBaseUrl: DEFAULT.appBaseUrl,
      secret,
      transactionStore,
      sessionStore,
      routes: getDefaultRoutes()
    });
  });

  // ---------------------------------------------------------------------------
  // passwordlessDbOtpChallenge
  // ---------------------------------------------------------------------------

  describe("passwordlessDbOtpChallenge", () => {
    it("sends email and connection in request body and returns authSession", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ auth_session: DEFAULT.authSession });
        })
      );

      const result = await authClient.passwordlessDbOtpChallenge({
        email: DEFAULT.email,
        connection: DEFAULT.connection
      });

      expect(capturedBody.client_id).toBe(DEFAULT.clientId);
      expect(capturedBody.client_secret).toBe(DEFAULT.clientSecret);
      expect(capturedBody.connection).toBe(DEFAULT.connection);
      expect(capturedBody.email).toBe(DEFAULT.email);
      expect(capturedBody.phone_number).toBeUndefined();
      expect(capturedBody.allow_signup).toBe(false);
      expect(result.authSession).toBe(DEFAULT.authSession);
    });

    it("reads auth_session (snake_case) from Auth0 response and maps to authSession", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          HttpResponse.json({ auth_session: "real-auth-session" })
        )
      );

      const result = await authClient.passwordlessDbOtpChallenge({
        email: DEFAULT.email,
        connection: DEFAULT.connection
      });

      expect(result.authSession).toBe("real-auth-session");
    });

    it("sends phone_number (snake_case) when phoneNumber option is provided", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ auth_session: DEFAULT.authSession });
        })
      );

      await authClient.passwordlessDbOtpChallenge({
        phoneNumber: DEFAULT.phoneNumber,
        connection: DEFAULT.connection
      });

      expect(capturedBody.phone_number).toBe(DEFAULT.phoneNumber);
      expect(capturedBody.email).toBeUndefined();
    });

    it("sends delivery_method when deliveryMethod option is provided", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ auth_session: DEFAULT.authSession });
        })
      );

      await authClient.passwordlessDbOtpChallenge({
        phoneNumber: DEFAULT.phoneNumber,
        connection: DEFAULT.connection,
        deliveryMethod: "voice"
      });

      expect(capturedBody.delivery_method).toBe("voice");
    });

    it("does not send delivery_method when not provided", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ auth_session: DEFAULT.authSession });
        })
      );

      await authClient.passwordlessDbOtpChallenge({
        phoneNumber: DEFAULT.phoneNumber,
        connection: DEFAULT.connection
      });

      expect(capturedBody.delivery_method).toBeUndefined();
    });

    it("sends allow_signup: true when allowSignup option is provided", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ auth_session: DEFAULT.authSession });
        })
      );

      await authClient.passwordlessDbOtpChallenge({
        email: DEFAULT.email,
        connection: DEFAULT.connection,
        allowSignup: true
      });

      expect(capturedBody.allow_signup).toBe(true);
    });

    it("defaults allow_signup to false when not provided", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ auth_session: DEFAULT.authSession });
        })
      );

      await authClient.passwordlessDbOtpChallenge({
        email: DEFAULT.email,
        connection: DEFAULT.connection
      });

      expect(capturedBody.allow_signup).toBe(false);
    });

    it("returns authSession (200-always contract) even when user does not exist", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          HttpResponse.json({ auth_session: "fake-auth-session-non-existent" })
        )
      );

      const result = await authClient.passwordlessDbOtpChallenge({
        email: "nonexistent@example.com",
        connection: DEFAULT.connection,
        allowSignup: false
      });

      expect(result.authSession).toBe("fake-auth-session-non-existent");
    });

    it("throws PasswordlessDbChallengeError on invalid_connection", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_connection",
              error_description: "Connection is not a database connection."
            },
            { status: 400 }
          )
        )
      );

      await expect(
        authClient.passwordlessDbOtpChallenge({
          email: DEFAULT.email,
          connection: "not-a-db-connection"
        })
      ).rejects.toMatchObject({
        name: "PasswordlessDbChallengeError",
        error: "invalid_connection",
        error_description: "Connection is not a database connection."
      });
    });

    it("throws PasswordlessDbChallengeError on invalid_request", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_request",
              error_description: "Phone provider not configured."
            },
            { status: 400 }
          )
        )
      );

      await expect(
        authClient.passwordlessDbOtpChallenge({
          phoneNumber: DEFAULT.phoneNumber,
          connection: DEFAULT.connection
        })
      ).rejects.toMatchObject({
        name: "PasswordlessDbChallengeError",
        error: "invalid_request"
      });
    });

    it("throws PasswordlessDbChallengeError with unexpected_error on network failure", async () => {
      server.use(http.post(CHALLENGE_URL, () => HttpResponse.error()));

      await expect(
        authClient.passwordlessDbOtpChallenge({
          email: DEFAULT.email,
          connection: DEFAULT.connection
        })
      ).rejects.toMatchObject({
        name: "PasswordlessDbChallengeError",
        error: "unexpected_error"
      });
    });

    it("throws PasswordlessDbChallengeError with unexpected_error on 200 with non-JSON body", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          new HttpResponse("<!DOCTYPE html><html>error</html>", {
            status: 200,
            headers: { "Content-Type": "text/html" }
          })
        )
      );

      await expect(
        authClient.passwordlessDbOtpChallenge({
          email: DEFAULT.email,
          connection: DEFAULT.connection
        })
      ).rejects.toMatchObject({
        name: "PasswordlessDbChallengeError",
        error: "unexpected_error"
      });
    });
  });

  // ---------------------------------------------------------------------------
  // passwordlessDbGetToken
  // ---------------------------------------------------------------------------

  describe("passwordlessDbGetToken", () => {
    it("sends auth_session, otp, grant_type and client_secret in request body", async () => {
      let capturedParams: URLSearchParams = new URLSearchParams();

      server.use(
        http.post(TOKEN_URL, async ({ request }) => {
          capturedParams = new URLSearchParams(await request.text());
          return HttpResponse.json({
            access_token: DEFAULT.accessToken,
            token_type: "Bearer",
            expires_in: 86400
          });
        })
      );

      const result = await authClient.passwordlessDbGetToken({
        authSession: DEFAULT.authSession,
        otp: DEFAULT.otp
      });

      expect(capturedParams.get("auth_session")).toBe(DEFAULT.authSession);
      expect(capturedParams.get("otp")).toBe(DEFAULT.otp);
      expect(capturedParams.get("grant_type")).toBe(
        "http://auth0.com/oauth/grant-type/passwordless/otp"
      );
      expect(capturedParams.get("client_secret")).toBe(DEFAULT.clientSecret);
      expect(result.access_token).toBe(DEFAULT.accessToken);
    });

    it("does not send realm or username — DB flow only uses auth_session", async () => {
      let capturedParams: URLSearchParams = new URLSearchParams();

      server.use(
        http.post(TOKEN_URL, async ({ request }) => {
          capturedParams = new URLSearchParams(await request.text());
          return HttpResponse.json({
            access_token: DEFAULT.accessToken,
            token_type: "Bearer",
            expires_in: 86400
          });
        })
      );

      await authClient.passwordlessDbGetToken({
        authSession: DEFAULT.authSession,
        otp: DEFAULT.otp
      });

      expect(capturedParams.get("realm")).toBeNull();
      expect(capturedParams.get("username")).toBeNull();
    });

    it("throws PasswordlessDbGetTokenError on invalid_request (wrong OTP)", async () => {
      server.use(
        http.post(TOKEN_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_request",
              error_description: "Invalid or expired OTP code."
            },
            { status: 400 }
          )
        )
      );

      await expect(
        authClient.passwordlessDbGetToken({
          authSession: DEFAULT.authSession,
          otp: "wrong-otp"
        })
      ).rejects.toMatchObject({
        name: "PasswordlessDbGetTokenError",
        error: "invalid_request",
        error_description: "Invalid or expired OTP code."
      });
    });

    it("throws PasswordlessDbGetTokenError on expired auth_session", async () => {
      server.use(
        http.post(TOKEN_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_request",
              error_description: "Invalid or expired OTP code."
            },
            { status: 400 }
          )
        )
      );

      await expect(
        authClient.passwordlessDbGetToken({
          authSession: "expired-session-token",
          otp: DEFAULT.otp
        })
      ).rejects.toMatchObject({
        name: "PasswordlessDbGetTokenError",
        error: "invalid_request"
      });
    });

    it("throws PasswordlessDbGetTokenError with discovery_error on discovery failure", async () => {
      server.use(
        http.get(
          `https://${DEFAULT.domain}/.well-known/openid-configuration`,
          () => HttpResponse.error()
        )
      );

      const freshSecret = await generateSecret(32);
      const freshClient = new AuthClient({
        domain: DEFAULT.domain,
        clientId: DEFAULT.clientId,
        clientSecret: DEFAULT.clientSecret,
        appBaseUrl: DEFAULT.appBaseUrl,
        secret: freshSecret,
        transactionStore: new TransactionStore({ secret: freshSecret }),
        sessionStore: new StatelessSessionStore({ secret: freshSecret }),
        routes: getDefaultRoutes()
      });

      await expect(
        freshClient.passwordlessDbGetToken({
          authSession: DEFAULT.authSession,
          otp: DEFAULT.otp
        })
      ).rejects.toMatchObject({
        name: "PasswordlessDbGetTokenError",
        error: "discovery_error"
      });
    });

    it("throws MfaRequiredError when Auth0 returns mfa_required", async () => {
      server.use(
        http.post(TOKEN_URL, () =>
          HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "Multi-factor authentication required.",
              mfa_token: "raw-mfa-token"
            },
            { status: 403 }
          )
        )
      );

      await expect(
        authClient.passwordlessDbGetToken({
          authSession: DEFAULT.authSession,
          otp: DEFAULT.otp
        })
      ).rejects.toMatchObject({ name: "MfaRequiredError" });
    });

    it("blocked user: challenge succeeds (200-always) then getToken throws invalid_request", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          HttpResponse.json({ auth_session: "fake-blocked-session" })
        ),
        http.post(TOKEN_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_request",
              error_description: "Invalid or expired OTP code."
            },
            { status: 400 }
          )
        )
      );

      const challenge = await authClient.passwordlessDbOtpChallenge({
        email: DEFAULT.email,
        connection: DEFAULT.connection
      });
      expect(challenge.authSession).toBe("fake-blocked-session");

      await expect(
        authClient.passwordlessDbGetToken({
          authSession: challenge.authSession,
          otp: DEFAULT.otp
        })
      ).rejects.toMatchObject({
        name: "PasswordlessDbGetTokenError",
        error: "invalid_request"
      });
    });
  });
});
