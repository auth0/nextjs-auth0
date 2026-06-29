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

import type { PasswordlessClient } from "../../types/index.js";

const DEFAULT = {
  appBaseUrl: "http://localhost:3000",
  email: "user@example.com",
  phoneNumber: "+14155550100",
  connection: "my-db-connection",
  authSession: "opaque-auth-session-token",
  otp: "123456"
};

const CHALLENGE_ROUTE = `${DEFAULT.appBaseUrl}/auth/passwordless/otp/challenge`;
const TOKEN_ROUTE = `${DEFAULT.appBaseUrl}/auth/passwordless/otp/token`;

const server = setupServer();

let originalChallengeRoute: string | undefined;
let originalTokenRoute: string | undefined;

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });

  originalChallengeRoute =
    process.env.NEXT_PUBLIC_PASSWORDLESS_DB_OTP_CHALLENGE_ROUTE;
  originalTokenRoute = process.env.NEXT_PUBLIC_PASSWORDLESS_DB_GET_TOKEN_ROUTE;

  process.env.NEXT_PUBLIC_PASSWORDLESS_DB_OTP_CHALLENGE_ROUTE = CHALLENGE_ROUTE;
  process.env.NEXT_PUBLIC_PASSWORDLESS_DB_GET_TOKEN_ROUTE = TOKEN_ROUTE;
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  if (originalChallengeRoute === undefined) {
    delete process.env.NEXT_PUBLIC_PASSWORDLESS_DB_OTP_CHALLENGE_ROUTE;
  } else {
    process.env.NEXT_PUBLIC_PASSWORDLESS_DB_OTP_CHALLENGE_ROUTE =
      originalChallengeRoute;
  }
  if (originalTokenRoute === undefined) {
    delete process.env.NEXT_PUBLIC_PASSWORDLESS_DB_GET_TOKEN_ROUTE;
  } else {
    process.env.NEXT_PUBLIC_PASSWORDLESS_DB_GET_TOKEN_ROUTE =
      originalTokenRoute;
  }
  server.close();
});

describe("ClientPasswordlessClient — DB OTP methods", () => {
  let client: PasswordlessClient;

  beforeEach(async () => {
    const { passwordless } = await import("./index.js");
    client = passwordless;
  });

  // ---------------------------------------------------------------------------
  // challengeWithEmail()
  // ---------------------------------------------------------------------------

  describe("challengeWithEmail", () => {
    it("sends email and connection to the challenge route and returns authSession", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_ROUTE, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ authSession: DEFAULT.authSession });
        })
      );

      const result = await client.challengeWithEmail({
        email: DEFAULT.email,
        connection: DEFAULT.connection
      });

      expect(capturedBody.email).toBe(DEFAULT.email);
      expect(capturedBody.connection).toBe(DEFAULT.connection);
      expect(result.authSession).toBe(DEFAULT.authSession);
    });

    it("sends allowSignup when provided", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_ROUTE, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ authSession: DEFAULT.authSession });
        })
      );

      await client.challengeWithEmail({
        email: DEFAULT.email,
        connection: DEFAULT.connection,
        allowSignup: true
      });

      expect(capturedBody.allowSignup).toBe(true);
    });

    it("succeeds silently for non-existent user with allowSignup false (200-always contract)", async () => {
      server.use(
        http.post(CHALLENGE_ROUTE, () =>
          HttpResponse.json({ authSession: DEFAULT.authSession })
        )
      );

      const result = await client.challengeWithEmail({
        email: "nonexistent@example.com",
        connection: DEFAULT.connection,
        allowSignup: false
      });

      expect(result.authSession).toBe(DEFAULT.authSession);
    });

    it("throws PasswordlessDbChallengeError on API error", async () => {
      server.use(
        http.post(CHALLENGE_ROUTE, () =>
          HttpResponse.json(
            {
              error: "invalid_connection",
              error_description: "Connection is not a database connection."
            },
            { status: 400 }
          )
        )
      );

      const err = await client
        .challengeWithEmail({
          email: DEFAULT.email,
          connection: "not-a-db-connection"
        })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessDbChallengeError",
        error: "invalid_connection",
        error_description: "Connection is not a database connection."
      });
    });

    it("throws PasswordlessDbChallengeError on network failure", async () => {
      server.use(http.post(CHALLENGE_ROUTE, () => HttpResponse.error()));

      const err = await client
        .challengeWithEmail({
          email: DEFAULT.email,
          connection: DEFAULT.connection
        })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessDbChallengeError",
        error: "client_error"
      });
    });
  });

  // ---------------------------------------------------------------------------
  // challengeWithPhoneNumber()
  // ---------------------------------------------------------------------------

  describe("challengeWithPhoneNumber", () => {
    it("sends phoneNumber and connection to the challenge route and returns authSession", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_ROUTE, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ authSession: DEFAULT.authSession });
        })
      );

      const result = await client.challengeWithPhoneNumber({
        phoneNumber: DEFAULT.phoneNumber,
        connection: DEFAULT.connection
      });

      expect(capturedBody.phoneNumber).toBe(DEFAULT.phoneNumber);
      expect(capturedBody.connection).toBe(DEFAULT.connection);
      expect(result.authSession).toBe(DEFAULT.authSession);
    });

    it("sends deliveryMethod when provided", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(CHALLENGE_ROUTE, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ authSession: DEFAULT.authSession });
        })
      );

      await client.challengeWithPhoneNumber({
        phoneNumber: DEFAULT.phoneNumber,
        connection: DEFAULT.connection,
        deliveryMethod: "voice"
      });

      expect(capturedBody.deliveryMethod).toBe("voice");
    });

    it("throws PasswordlessDbChallengeError on API error", async () => {
      server.use(
        http.post(CHALLENGE_ROUTE, () =>
          HttpResponse.json(
            {
              error: "invalid_request",
              error_description: "Phone provider not configured."
            },
            { status: 400 }
          )
        )
      );

      const err = await client
        .challengeWithPhoneNumber({
          phoneNumber: DEFAULT.phoneNumber,
          connection: DEFAULT.connection
        })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessDbChallengeError",
        error: "invalid_request"
      });
    });

    it("throws PasswordlessDbChallengeError on network failure", async () => {
      server.use(http.post(CHALLENGE_ROUTE, () => HttpResponse.error()));

      const err = await client
        .challengeWithPhoneNumber({
          phoneNumber: DEFAULT.phoneNumber,
          connection: DEFAULT.connection
        })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessDbChallengeError",
        error: "client_error"
      });
    });
  });

  // ---------------------------------------------------------------------------
  // loginWithOtp()
  // ---------------------------------------------------------------------------

  describe("loginWithOtp", () => {
    it("sends authSession and otp to the token route", async () => {
      let capturedBody: Record<string, unknown> = {};

      server.use(
        http.post(TOKEN_ROUTE, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({ success: true });
        })
      );

      await client.loginWithOtp({
        authSession: DEFAULT.authSession,
        otp: DEFAULT.otp
      });

      expect(capturedBody.authSession).toBe(DEFAULT.authSession);
      expect(capturedBody.otp).toBe(DEFAULT.otp);
    });

    it("throws PasswordlessDbGetTokenError on invalid OTP", async () => {
      server.use(
        http.post(TOKEN_ROUTE, () =>
          HttpResponse.json(
            {
              error: "invalid_request",
              error_description: "Invalid or expired OTP code."
            },
            { status: 403 }
          )
        )
      );

      const err = await client
        .loginWithOtp({ authSession: DEFAULT.authSession, otp: "wrong" })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessDbGetTokenError",
        error: "invalid_request",
        error_description: "Invalid or expired OTP code."
      });
    });

    it("throws PasswordlessDbGetTokenError on expired auth_session", async () => {
      server.use(
        http.post(TOKEN_ROUTE, () =>
          HttpResponse.json(
            {
              error: "invalid_request",
              error_description: "Invalid or expired OTP code."
            },
            { status: 403 }
          )
        )
      );

      const err = await client
        .loginWithOtp({ authSession: "expired-session", otp: DEFAULT.otp })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessDbGetTokenError",
        error: "invalid_request"
      });
    });

    it("re-throws mfa_required raw object instead of wrapping as PasswordlessDbGetTokenError", async () => {
      server.use(
        http.post(TOKEN_ROUTE, () =>
          HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "Multi-factor authentication is required.",
              mfa_token: "encrypted-mfa-token-value"
            },
            { status: 403 }
          )
        )
      );

      const err = await client
        .loginWithOtp({ authSession: DEFAULT.authSession, otp: DEFAULT.otp })
        .catch((e) => e);

      expect(err.error).toBe("mfa_required");
      expect(err.mfa_token).toBe("encrypted-mfa-token-value");
      expect(err.name).not.toBe("PasswordlessDbGetTokenError");
    });

    it("throws PasswordlessDbGetTokenError on network failure", async () => {
      server.use(http.post(TOKEN_ROUTE, () => HttpResponse.error()));

      const err = await client
        .loginWithOtp({ authSession: DEFAULT.authSession, otp: DEFAULT.otp })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessDbGetTokenError",
        error: "client_error"
      });
    });
  });
});
