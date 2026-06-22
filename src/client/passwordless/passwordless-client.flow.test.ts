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
  verificationCode: "123456"
};

const server = setupServer();

let originalStartRoute: string | undefined;
let originalVerifyRoute: string | undefined;

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });

  originalStartRoute = process.env.NEXT_PUBLIC_PASSWORDLESS_START_ROUTE;
  originalVerifyRoute = process.env.NEXT_PUBLIC_PASSWORDLESS_VERIFY_ROUTE;
  process.env.NEXT_PUBLIC_PASSWORDLESS_START_ROUTE = `${DEFAULT.appBaseUrl}/auth/passwordless/start`;
  process.env.NEXT_PUBLIC_PASSWORDLESS_VERIFY_ROUTE = `${DEFAULT.appBaseUrl}/auth/passwordless/verify`;
});

afterEach(() => {
  server.resetHandlers();
});

afterAll(() => {
  if (originalStartRoute === undefined) {
    delete process.env.NEXT_PUBLIC_PASSWORDLESS_START_ROUTE;
  } else {
    process.env.NEXT_PUBLIC_PASSWORDLESS_START_ROUTE = originalStartRoute;
  }
  if (originalVerifyRoute === undefined) {
    delete process.env.NEXT_PUBLIC_PASSWORDLESS_VERIFY_ROUTE;
  } else {
    process.env.NEXT_PUBLIC_PASSWORDLESS_VERIFY_ROUTE = originalVerifyRoute;
  }
  server.close();
});

describe("ClientPasswordlessClient", () => {
  let client: PasswordlessClient;

  beforeEach(async () => {
    const { passwordless } = await import("./index.js");
    client = passwordless;
  });

  // ---------------------------------------------------------------------------
  // start()
  // ---------------------------------------------------------------------------

  describe("start", () => {
    it("sends email connection to the start route", async () => {
      let capturedBody: Record<string, string> = {};

      server.use(
        http.post(
          `${DEFAULT.appBaseUrl}/auth/passwordless/start`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, string>;
            return new HttpResponse(null, { status: 204 });
          }
        )
      );

      await client.start({
        connection: "email",
        email: DEFAULT.email,
        send: "code"
      });

      expect(capturedBody.connection).toBe("email");
      expect(capturedBody.email).toBe(DEFAULT.email);
      expect(capturedBody.send).toBe("code");
    });

    it("sends sms connection to the start route", async () => {
      let capturedBody: Record<string, string> = {};

      server.use(
        http.post(
          `${DEFAULT.appBaseUrl}/auth/passwordless/start`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, string>;
            return new HttpResponse(null, { status: 204 });
          }
        )
      );

      await client.start({
        connection: "sms",
        phoneNumber: DEFAULT.phoneNumber
      });

      expect(capturedBody.connection).toBe("sms");
      expect(capturedBody.phoneNumber).toBe(DEFAULT.phoneNumber);
    });

    it("throws PasswordlessStartError on Auth0 API error", async () => {
      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/passwordless/start`, () =>
          HttpResponse.json(
            {
              error: "bad.connection",
              error_description: "Connection not found."
            },
            { status: 400 }
          )
        )
      );

      const err = await client
        .start({ connection: "email", email: DEFAULT.email, send: "code" })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessStartError",
        error: "bad.connection",
        error_description: "Connection not found."
      });
    });

    it("throws PasswordlessStartError on network failure", async () => {
      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/passwordless/start`, () =>
          HttpResponse.error()
        )
      );

      const err = await client
        .start({ connection: "email", email: DEFAULT.email, send: "link" })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessStartError",
        error: "client_error"
      });
    });
  });

  // ---------------------------------------------------------------------------
  // verify()
  // ---------------------------------------------------------------------------

  describe("verify", () => {
    it("sends email connection to the verify route", async () => {
      let capturedBody: Record<string, string> = {};

      server.use(
        http.post(
          `${DEFAULT.appBaseUrl}/auth/passwordless/verify`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, string>;
            return HttpResponse.json({ success: true });
          }
        )
      );

      await client.verify({
        connection: "email",
        email: DEFAULT.email,
        verificationCode: DEFAULT.verificationCode
      });

      expect(capturedBody.connection).toBe("email");
      expect(capturedBody.email).toBe(DEFAULT.email);
      expect(capturedBody.verificationCode).toBe(DEFAULT.verificationCode);
    });

    it("sends sms connection to the verify route", async () => {
      let capturedBody: Record<string, string> = {};

      server.use(
        http.post(
          `${DEFAULT.appBaseUrl}/auth/passwordless/verify`,
          async ({ request }) => {
            capturedBody = (await request.json()) as Record<string, string>;
            return HttpResponse.json({ success: true });
          }
        )
      );

      await client.verify({
        connection: "sms",
        phoneNumber: DEFAULT.phoneNumber,
        verificationCode: DEFAULT.verificationCode
      });

      expect(capturedBody.connection).toBe("sms");
      expect(capturedBody.phoneNumber).toBe(DEFAULT.phoneNumber);
      expect(capturedBody.verificationCode).toBe(DEFAULT.verificationCode);
    });

    it("throws PasswordlessVerifyError on invalid_grant", async () => {
      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/passwordless/verify`, () =>
          HttpResponse.json(
            {
              error: "invalid_grant",
              error_description: "Wrong email or verification code."
            },
            { status: 403 }
          )
        )
      );

      const err = await client
        .verify({
          connection: "email",
          email: DEFAULT.email,
          verificationCode: "wrong-code"
        })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessVerifyError",
        error: "invalid_grant",
        error_description: "Wrong email or verification code."
      });
    });

    it("throws PasswordlessVerifyError on network failure", async () => {
      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/passwordless/verify`, () =>
          HttpResponse.error()
        )
      );

      const err = await client
        .verify({
          connection: "email",
          email: DEFAULT.email,
          verificationCode: DEFAULT.verificationCode
        })
        .catch((e) => e);

      expect(err).toMatchObject({
        name: "PasswordlessVerifyError",
        error: "client_error"
      });
    });

    it("re-throws mfa_required raw object instead of wrapping as PasswordlessVerifyError", async () => {
      server.use(
        http.post(`${DEFAULT.appBaseUrl}/auth/passwordless/verify`, () =>
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
        .verify({
          connection: "email",
          email: DEFAULT.email,
          verificationCode: DEFAULT.verificationCode
        })
        .catch((e) => e);

      expect(err.error).toBe("mfa_required");
      expect(err.mfa_token).toBe("encrypted-mfa-token-value");
      expect(err.name).not.toBe("PasswordlessVerifyError");
    });
  });
});
