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
  verificationCode: "123456",
  authSession: "opaque-auth-session",
  otp: "654321",
  connection: "my-db-connection"
};

const START_ROUTE = `${DEFAULT.appBaseUrl}/auth/passwordless/start`;
const VERIFY_ROUTE = `${DEFAULT.appBaseUrl}/auth/passwordless/verify`;
const CHALLENGE_ROUTE = `${DEFAULT.appBaseUrl}/auth/passwordless/otp/challenge`;
const TOKEN_ROUTE = `${DEFAULT.appBaseUrl}/auth/passwordless/otp/token`;

const server = setupServer();

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });

  process.env.NEXT_PUBLIC_PASSWORDLESS_START_ROUTE = START_ROUTE;
  process.env.NEXT_PUBLIC_PASSWORDLESS_VERIFY_ROUTE = VERIFY_ROUTE;
  process.env.NEXT_PUBLIC_PASSWORDLESS_DB_OTP_CHALLENGE_ROUTE = CHALLENGE_ROUTE;
  process.env.NEXT_PUBLIC_PASSWORDLESS_DB_GET_TOKEN_ROUTE = TOKEN_ROUTE;
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  delete process.env.NEXT_PUBLIC_PASSWORDLESS_START_ROUTE;
  delete process.env.NEXT_PUBLIC_PASSWORDLESS_VERIFY_ROUTE;
  delete process.env.NEXT_PUBLIC_PASSWORDLESS_DB_OTP_CHALLENGE_ROUTE;
  delete process.env.NEXT_PUBLIC_PASSWORDLESS_DB_GET_TOKEN_ROUTE;
  server.close();
});

describe("ClientPasswordlessClient — error JSON parse fallback paths", () => {
  let client: PasswordlessClient;

  beforeEach(async () => {
    const { passwordless } = await import("./index.js");
    client = passwordless;
  });

  // -------------------------------------------------------------------------
  // start() — error response with non-JSON body (json() fallback)
  // -------------------------------------------------------------------------

  describe("start() — json parse fallback on error", () => {
    it("throws PasswordlessStartError with client_error when error response body is not valid JSON", async () => {
      server.use(
        http.post(
          START_ROUTE,
          () =>
            new HttpResponse("Internal Server Error", {
              status: 500,
              headers: { "Content-Type": "text/plain" }
            })
        )
      );

      const err = await client
        .start({ connection: "email", email: DEFAULT.email, send: "code" })
        .catch((e) => e);

      expect(err.name).toBe("PasswordlessStartError");
      // The json() parse failed so we fall back to the default client_error values
      expect(err.error).toBe("client_error");
    });
  });

  // -------------------------------------------------------------------------
  // verify() — error response with non-JSON body (json() fallback)
  // -------------------------------------------------------------------------

  describe("verify() — json parse fallback on error", () => {
    it("throws PasswordlessVerifyError with client_error when error response body is not valid JSON", async () => {
      server.use(
        http.post(
          VERIFY_ROUTE,
          () =>
            new HttpResponse("Internal Server Error", {
              status: 500,
              headers: { "Content-Type": "text/plain" }
            })
        )
      );

      const err = await client
        .verify({
          connection: "email",
          email: DEFAULT.email,
          verificationCode: DEFAULT.verificationCode
        })
        .catch((e) => e);

      expect(err.name).toBe("PasswordlessVerifyError");
      expect(err.error).toBe("client_error");
    });
  });

  // -------------------------------------------------------------------------
  // #sendChallenge() — error response with non-JSON body (json() fallback)
  // -------------------------------------------------------------------------

  describe("challengeWithEmail() — json parse fallback on error", () => {
    it("throws PasswordlessDbChallengeError with client_error when error response body is not valid JSON", async () => {
      server.use(
        http.post(
          CHALLENGE_ROUTE,
          () =>
            new HttpResponse("Internal Server Error", {
              status: 500,
              headers: { "Content-Type": "text/plain" }
            })
        )
      );

      const err = await client
        .challengeWithEmail({
          email: DEFAULT.email,
          connection: DEFAULT.connection
        })
        .catch((e) => e);

      expect(err.name).toBe("PasswordlessDbChallengeError");
      expect(err.error).toBe("client_error");
    });
  });

  // -------------------------------------------------------------------------
  // loginWithOtp() — mfa_required pass-through
  // -------------------------------------------------------------------------

  describe("loginWithOtp() — network error (non-Error throw path)", () => {
    it("throws PasswordlessDbGetTokenError when fetch rejects with a non-Error value", async () => {
      // MSW's HttpResponse.error() causes fetch to reject with a TypeError (which IS an Error).
      // To hit the non-Error branch of `e instanceof Error ? e.message : "Network error"`
      // we need to mock global fetch directly.
      const originalFetch = global.fetch;
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      global.fetch = () => Promise.reject("string rejection");

      const err = await client
        .loginWithOtp({ authSession: DEFAULT.authSession, otp: DEFAULT.otp })
        .catch((e) => e);

      global.fetch = originalFetch;

      expect(err.name).toBe("PasswordlessDbGetTokenError");
      expect(err.error).toBe("client_error");
    });
  });

  describe("loginWithOtp() — mfa_required pass-through", () => {
    it("re-throws mfa_required as raw object", async () => {
      server.use(
        http.post(TOKEN_ROUTE, () =>
          HttpResponse.json(
            {
              error: "mfa_required",
              error_description: "MFA is required.",
              mfa_token: "test-mfa-token"
            },
            { status: 403 }
          )
        )
      );

      const err = await client
        .loginWithOtp({
          authSession: DEFAULT.authSession,
          otp: DEFAULT.otp
        })
        .catch((e) => e);

      expect(err.error).toBe("mfa_required");
      expect(err.mfa_token).toBe("test-mfa-token");
      expect(err.name).not.toBe("PasswordlessDbGetTokenError");
    });

    it("throws PasswordlessDbGetTokenError when error response body is not valid JSON", async () => {
      server.use(
        http.post(
          TOKEN_ROUTE,
          () =>
            new HttpResponse("Internal Server Error", {
              status: 500,
              headers: { "Content-Type": "text/plain" }
            })
        )
      );

      const err = await client
        .loginWithOtp({ authSession: DEFAULT.authSession, otp: DEFAULT.otp })
        .catch((e) => e);

      expect(err.name).toBe("PasswordlessDbGetTokenError");
      expect(err.error).toBe("client_error");
    });
  });
});
