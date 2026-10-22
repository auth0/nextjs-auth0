/**
 * Flow tests for passkey signup identifier verification (inline OTP).
 * Covers the AuthClient core methods and the passkey route handlers:
 * verification_required on the signup challenge, verification codes on the
 * token exchange, retryable vs terminal error classification and 429 handling.
 */
import { NextRequest } from "next/server.js";
import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";
import * as jose from "jose";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import { InvalidRequestError, PasskeyGetTokenError } from "../errors/index.js";
import {
  createAuthorizationServerMetadata,
  getDefaultRoutes,
  setupMswLifecycle
} from "../test/defaults.js";
import { generateSecret } from "../test/utils.js";
import type { PasskeyGetTokenOptions } from "../types/index.js";
import { generateDpopKeyPair } from "../utils/dpopRetry.js";
import { AuthClient } from "./auth-client.js";
import { StatelessSessionStore } from "./session/stateless-session-store.js";
import { TransactionStore } from "./transaction-store.js";

const DEFAULT = {
  domain: "auth0.local",
  clientId: "test-client-id",
  clientSecret: "test-client-secret",
  appBaseUrl: "http://localhost:3000",
  sub: "passkeys|test-user-id",
  sid: "test-sid",
  authSession: "test-auth-session-token",
  accessToken: "test-access-token"
};

const REGISTER_URL = `https://${DEFAULT.domain}/passkey/register`;
const CHALLENGE_URL = `https://${DEFAULT.domain}/passkey/challenge`;
const TOKEN_URL = `https://${DEFAULT.domain}/oauth/token`;

const MOCK_AUTH_RESPONSE = {
  id: "cred-id",
  rawId: "cred-raw-id",
  type: "public-key" as const,
  response: {
    clientDataJSON: "clientDataJSON-base64url",
    attestationObject: "attestationObject-base64url"
  }
};

const WRONG_CODE_BODY = {
  error: "invalid_grant",
  error_description: "Invalid or expired session",
  auth_session: DEFAULT.authSession,
  verification_required: ["email"]
};

let keyPair: jose.GenerateKeyPairResult;

const server = setupServer(
  http.get(`https://${DEFAULT.domain}/.well-known/openid-configuration`, () =>
    HttpResponse.json(createAuthorizationServerMetadata(DEFAULT.domain))
  ),
  http.get(`https://${DEFAULT.domain}/.well-known/jwks.json`, async () => {
    const jwk = await jose.exportJWK(keyPair.publicKey);
    return HttpResponse.json({
      keys: [{ ...jwk, kid: "test-key-1", alg: "RS256", use: "sig" }]
    });
  })
);

setupMswLifecycle(server);

beforeAll(async () => {
  keyPair = await jose.generateKeyPair("RS256");
});

async function tokenResponse() {
  const idToken = await new jose.SignJWT({ sub: DEFAULT.sub, sid: DEFAULT.sid })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(`https://${DEFAULT.domain}`)
    .setAudience(DEFAULT.clientId)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(keyPair.privateKey);
  return {
    access_token: DEFAULT.accessToken,
    token_type: "Bearer",
    expires_in: 86400,
    scope: "openid profile email",
    id_token: idToken
  };
}

async function createAuthClient(extra: Record<string, unknown> = {}) {
  const secret = await generateSecret(32);
  return new AuthClient({
    domain: DEFAULT.domain,
    clientId: DEFAULT.clientId,
    clientSecret: DEFAULT.clientSecret,
    appBaseUrl: DEFAULT.appBaseUrl,
    secret,
    transactionStore: new TransactionStore({ secret }),
    sessionStore: new StatelessSessionStore({ secret }),
    routes: getDefaultRoutes(),
    ...extra
  });
}

function postRequest(path: string, body: unknown) {
  return new NextRequest(new URL(path, DEFAULT.appBaseUrl), {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json" }
  });
}

/** Mocks /oauth/token, recording each request body. */
function mockToken(
  respond: () => Response | Promise<Response>
): Record<string, any>[] {
  const bodies: Record<string, any>[] = [];
  server.use(
    http.post(TOKEN_URL, async ({ request }) => {
      bodies.push((await request.json()) as Record<string, any>);
      return respond();
    })
  );
  return bodies;
}

describe("passkey identifier verification", () => {
  let authClient: AuthClient;

  beforeEach(async () => {
    authClient = await createAuthClient();
  });

  function getToken(extra: Partial<PasskeyGetTokenOptions> = {}) {
    return authClient.passkeyGetToken(
      {
        authSession: DEFAULT.authSession,
        authResponse: MOCK_AUTH_RESPONSE,
        ...extra
      },
      new RequestCookies(new Headers()),
      new ResponseCookies(new Headers())
    );
  }

  async function getTokenError(
    extra: Partial<PasskeyGetTokenOptions> = {}
  ): Promise<PasskeyGetTokenError> {
    const err = await getToken(extra).catch((e) => e);
    expect(err).toBeInstanceOf(PasskeyGetTokenError);
    return err;
  }

  // ---------------------------------------------------------------------------
  // passkeyRegister
  // ---------------------------------------------------------------------------

  describe("passkeyRegister", () => {
    it.each([
      ["absent", {}, undefined],
      ["email only", { verification_required: ["email"] }, ["email"]],
      ["phone only", { verification_required: ["phone"] }, ["phone"]],
      [
        "email and phone",
        { verification_required: ["email", "phone"] },
        ["email", "phone"]
      ]
    ])(
      "maps verification_required when %s",
      async (_label, extra, expected) => {
        server.use(
          http.post(REGISTER_URL, () =>
            HttpResponse.json({
              auth_session: DEFAULT.authSession,
              authn_params_public_key: { challenge: "abc" },
              ...extra
            })
          )
        );

        const challenge = await authClient.passkeyRegister();

        expect(challenge.verificationRequired).toEqual(expected);
        if (expected === undefined) {
          expect(challenge).not.toHaveProperty("verificationRequired");
        }
      }
    );

    it.each(["text", "voice"] as const)(
      "forwards deliveryMethod %s as delivery_method",
      async (deliveryMethod) => {
        let body: Record<string, unknown> = {};
        server.use(
          http.post(REGISTER_URL, async ({ request }) => {
            body = (await request.json()) as Record<string, unknown>;
            return HttpResponse.json({
              auth_session: DEFAULT.authSession,
              authn_params_public_key: {}
            });
          })
        );

        await authClient.passkeyRegister({ deliveryMethod });

        expect(body.delivery_method).toBe(deliveryMethod);
      }
    );

    it("omits delivery_method when not set", async () => {
      let body: Record<string, unknown> = {};
      server.use(
        http.post(REGISTER_URL, async ({ request }) => {
          body = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            auth_session: DEFAULT.authSession,
            authn_params_public_key: {}
          });
        })
      );

      await authClient.passkeyRegister();

      expect(body).not.toHaveProperty("delivery_method");
    });

    it("surfaces Auth0's error for an unsupported delivery method", async () => {
      server.use(
        http.post(REGISTER_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_request",
              error_description:
                "The requested media is not supported for this connection"
            },
            { status: 400 }
          )
        )
      );

      await expect(
        authClient.passkeyRegister({ deliveryMethod: "voice" })
      ).rejects.toMatchObject({
        name: "PasskeyRegisterError",
        error: "invalid_request"
      });
    });

    it.each([
      [
        "plain text",
        "too_many_requests",
        () => new HttpResponse("Too Many Requests", { status: 429 }),
        "Too many requests. Please try again later."
      ],
      [
        "JSON without an error",
        "too_many_requests",
        () =>
          HttpResponse.json(
            { message: "slow down", error_description: "slow down" },
            { status: 429 }
          ),
        "slow down"
      ],
      [
        "JSON",
        "too_many_requests",
        () =>
          HttpResponse.json(
            { error: "too_many_requests", error_description: "slow down" },
            { status: 429 }
          ),
        "slow down"
      ],
      [
        "JSON access_denied",
        "too_many_requests",
        () =>
          HttpResponse.json(
            {
              error: "access_denied",
              error_description: "Global rate limit exceeded"
            },
            { status: 429 }
          ),
        "Global rate limit exceeded"
      ],
      [
        "JSON too_many_attempts",
        "too_many_attempts",
        () =>
          HttpResponse.json(
            {
              error: "too_many_attempts",
              error_description: "Your account has been blocked"
            },
            { status: 429 }
          ),
        "Your account has been blocked"
      ]
    ])("raises a %s 429 as %s", async (_label, error, respond, description) => {
      server.use(http.post(REGISTER_URL, respond));

      await expect(authClient.passkeyRegister()).rejects.toMatchObject({
        name: "PasskeyRegisterError",
        error,
        error_description: description
      });
    });

    it("keeps Auth0's JSON error body as cause on a 429", async () => {
      const body = {
        error: "access_denied",
        error_description: "Global rate limit exceeded"
      };
      server.use(
        http.post(REGISTER_URL, () => HttpResponse.json(body, { status: 429 }))
      );

      const err = await authClient.passkeyRegister().catch((e) => e);

      expect(err.error).toBe("too_many_requests");
      expect(err.cause).toEqual(body);
    });

    it("has no cause on a plain-text 429", async () => {
      server.use(
        http.post(
          REGISTER_URL,
          () => new HttpResponse("Too Many Requests", { status: 429 })
        )
      );

      const err = await authClient.passkeyRegister().catch((e) => e);

      expect(err.cause).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // passkeyChallenge
  // ---------------------------------------------------------------------------

  describe("passkeyChallenge", () => {
    it("raises too_many_requests on a plain-text 429", async () => {
      server.use(
        http.post(
          CHALLENGE_URL,
          () => new HttpResponse("Too Many Requests", { status: 429 })
        )
      );

      await expect(authClient.passkeyChallenge()).rejects.toMatchObject({
        name: "PasskeyChallengeError",
        error: "too_many_requests",
        error_description: "Too many requests. Please try again later."
      });
    });

    it("raises a JSON 429 as too_many_requests and keeps the body as cause", async () => {
      const body = {
        error: "too_many_requests",
        error_description: "Global rate limit exceeded"
      };
      server.use(
        http.post(CHALLENGE_URL, () => HttpResponse.json(body, { status: 429 }))
      );

      const err = await authClient.passkeyChallenge().catch((e) => e);

      expect(err.name).toBe("PasskeyChallengeError");
      expect(err.error).toBe("too_many_requests");
      expect(err.error_description).toBe("Global rate limit exceeded");
      expect(err.cause).toEqual(body);
    });
  });

  // ---------------------------------------------------------------------------
  // passkeyGetToken: request
  // ---------------------------------------------------------------------------

  describe("passkeyGetToken request", () => {
    it("forwards verification codes", async () => {
      const bodies = mockToken(async () =>
        HttpResponse.json(await tokenResponse())
      );

      await getToken({ verification: { email: "123456", phone: "654321" } });

      expect(bodies[0].verification).toEqual({
        email: "123456",
        phone: "654321"
      });
    });

    it("drops blank and undefined codes", async () => {
      const bodies = mockToken(async () =>
        HttpResponse.json(await tokenResponse())
      );

      await getToken({ verification: { email: "123456", phone: "   " } });

      expect(bodies[0].verification).toEqual({ email: "123456" });
    });

    it.each([
      ["undefined", undefined],
      ["empty", {}],
      ["all blank", { email: "", phone: " " }],
      ["all undefined", { email: undefined }]
    ])("omits verification when %s", async (_label, verification) => {
      const bodies = mockToken(async () =>
        HttpResponse.json(await tokenResponse())
      );

      await getToken({ verification });

      expect(bodies[0]).not.toHaveProperty("verification");
    });

    it.each([
      ["phone_number key", { phone_number: "123456" }],
      ["extra key", { email: "123456", otp: "654321" }],
      ["wrong case", { EMAIL: "123456" }],
      ["numeric code", { email: 123456 }],
      ["array code", { email: ["123456"] }],
      ["non-object", "123456"]
    ])("rejects %s before sending a request", async (_label, verification) => {
      const bodies = mockToken(() => HttpResponse.json({}));

      const err = await getToken({ verification: verification as any }).catch(
        (e) => e
      );

      expect(err).toBeInstanceOf(InvalidRequestError);
      expect(err.message).not.toContain("123456");
      expect(bodies).toHaveLength(0);
    });

    it("sends verification alongside a DPoP proof", async () => {
      authClient = await createAuthClient({
        useDPoP: true,
        dpopKeyPair: await generateDpopKeyPair()
      });
      let dpopHeader: string | null = null;
      let body: Record<string, unknown> = {};
      server.use(
        http.post(TOKEN_URL, async ({ request }) => {
          dpopHeader = request.headers.get("dpop");
          body = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...(await tokenResponse()),
            token_type: "DPoP"
          });
        })
      );

      await getToken({ verification: { email: "123456" } });

      expect(body.verification).toEqual({ email: "123456" });
      expect(dpopHeader).not.toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // passkeyGetToken: error classification
  // ---------------------------------------------------------------------------

  describe("passkeyGetToken errors", () => {
    it("marks a wrong code as retryable with the session and remaining identifiers", async () => {
      mockToken(() => HttpResponse.json(WRONG_CODE_BODY, { status: 400 }));

      const err = await getTokenError({ verification: { email: "000000" } });

      expect(err.error).toBe("invalid_grant");
      expect(err.isRetryable).toBe(true);
      expect(err.authSession).toBe(DEFAULT.authSession);
      expect(err.verificationRequired).toEqual(["email"]);
    });

    it("never exposes the auth session in the message or toJSON()", async () => {
      mockToken(() => HttpResponse.json(WRONG_CODE_BODY, { status: 400 }));

      const err = await getTokenError({ verification: { email: "000000" } });

      expect(err.message).not.toContain(DEFAULT.authSession);
      expect(JSON.stringify(err)).not.toContain(DEFAULT.authSession);
      expect(JSON.stringify(err.toJSON())).not.toContain(DEFAULT.authSession);
      expect(err.cause?.auth_session).toBe(DEFAULT.authSession);
    });

    it("lists every identifier still pending", async () => {
      mockToken(() =>
        HttpResponse.json(
          { ...WRONG_CODE_BODY, verification_required: ["email", "phone"] },
          { status: 400 }
        )
      );

      const err = await getTokenError({
        verification: { email: "1", phone: "2" }
      });

      expect(err.verificationRequired).toEqual(["email", "phone"]);
    });

    it.each([
      [
        "exhausted invalid_grant (400)",
        400,
        {
          error: "invalid_grant",
          error_description: "Invalid or expired session"
        }
      ],
      [
        "unknown session (403)",
        403,
        {
          error: "invalid_grant",
          error_description: "Invalid or expired session"
        }
      ],
      [
        "missing code invalid_request",
        400,
        {
          error: "invalid_request",
          error_description: "Missing required parameter: verification.email"
        }
      ],
      [
        "server_error (500)",
        500,
        { error: "server_error", error_description: "unavailable" }
      ]
    ])("does not mark %s as retryable", async (_label, status, body) => {
      mockToken(() => HttpResponse.json(body, { status }));

      const err = await getTokenError({ verification: { email: "000000" } });

      expect(err.error).toBe(body.error);
      expect(err.isRetryable).toBe(false);
      expect(err.authSession).toBeUndefined();
      expect(err.verificationRequired).toBeUndefined();
    });

    it.each([
      [
        "plain text",
        "too_many_requests",
        () => new HttpResponse("Too Many Requests", { status: 429 }),
        "Too many requests. Please try again later."
      ],
      [
        "JSON without an error",
        "too_many_requests",
        () => HttpResponse.json({ message: "slow down" }, { status: 429 }),
        "Too many requests. Please try again later."
      ],
      [
        "JSON access_denied",
        "too_many_requests",
        () =>
          HttpResponse.json(
            {
              error: "access_denied",
              error_description: "Global rate limit exceeded"
            },
            { status: 429 }
          ),
        "Global rate limit exceeded"
      ],
      [
        "JSON too_many_attempts",
        "too_many_attempts",
        () =>
          HttpResponse.json(
            {
              error: "too_many_attempts",
              error_description: "Your account has been blocked"
            },
            { status: 429 }
          ),
        "Your account has been blocked"
      ]
    ])("raises a %s 429 as %s", async (_label, error, respond, description) => {
      mockToken(respond);

      const err = await getTokenError();

      expect(err.error).toBe(error);
      expect(err.error_description).toBe(description);
      expect(err.isRetryable).toBe(false);
      expect(err.authSession).toBeUndefined();
    });

    it("keeps Auth0's JSON error body as cause on a 429", async () => {
      const body = {
        error: "access_denied",
        error_description: "Too Many Requests"
      };
      mockToken(() => HttpResponse.json(body, { status: 429 }));

      const err = await getTokenError();

      expect(err.error).toBe("too_many_requests");
      expect(err.cause).toEqual(body);
    });

    it("succeeds on the same session after a wrong code is corrected", async () => {
      let call = 0;
      const bodies = mockToken(async () =>
        call++ === 0
          ? HttpResponse.json(WRONG_CODE_BODY, { status: 400 })
          : HttpResponse.json(await tokenResponse())
      );

      const err = await getTokenError({ verification: { email: "000000" } });
      expect(err.isRetryable).toBe(true);

      await getToken({
        authSession: err.authSession!,
        verification: { email: "123456" }
      });

      expect(bodies).toHaveLength(2);
      expect(bodies[0].auth_session).toBe(bodies[1].auth_session);
      expect(bodies[0].authn_response).toEqual(bodies[1].authn_response);
      expect(bodies[0].verification).toEqual({ email: "000000" });
      expect(bodies[1].verification).toEqual({ email: "123456" });
    });
  });

  // ---------------------------------------------------------------------------
  // Route handlers
  // ---------------------------------------------------------------------------

  describe("route handlers", () => {
    it("register returns verificationRequired and forwards deliveryMethod", async () => {
      let body: Record<string, unknown> = {};
      server.use(
        http.post(REGISTER_URL, async ({ request }) => {
          body = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            auth_session: DEFAULT.authSession,
            authn_params_public_key: { challenge: "abc" },
            verification_required: ["phone"]
          });
        })
      );

      const res = await authClient.handler(
        postRequest("/auth/passkey/register", {
          phoneNumber: "+15555550100",
          deliveryMethod: "voice"
        })
      );

      expect(res.status).toBe(200);
      expect((await res.json()).verificationRequired).toEqual(["phone"]);
      expect(body.delivery_method).toBe("voice");
    });

    it("register returns 429 when rate limited", async () => {
      server.use(
        http.post(
          REGISTER_URL,
          () => new HttpResponse("Too Many Requests", { status: 429 })
        )
      );

      const res = await authClient.handler(
        postRequest("/auth/passkey/register", {})
      );

      expect(res.status).toBe(429);
      expect((await res.json()).error).toBe("too_many_requests");
    });

    it("challenge returns 429 when rate limited", async () => {
      server.use(
        http.post(
          CHALLENGE_URL,
          () => new HttpResponse("Too Many Requests", { status: 429 })
        )
      );

      const res = await authClient.handler(
        postRequest("/auth/passkey/challenge", {})
      );

      expect(res.status).toBe(429);
      expect((await res.json()).error).toBe("too_many_requests");
    });

    it("get-token forwards verification codes", async () => {
      const bodies = mockToken(async () =>
        HttpResponse.json(await tokenResponse())
      );

      const res = await authClient.handler(
        postRequest("/auth/passkey/get-token", {
          authSession: DEFAULT.authSession,
          authResponse: MOCK_AUTH_RESPONSE,
          verification: { email: "123456" }
        })
      );

      expect(res.status).toBe(200);
      expect(bodies[0].verification).toEqual({ email: "123456" });
    });

    it("get-token returns auth_session and verification_required on a wrong code", async () => {
      mockToken(() => HttpResponse.json(WRONG_CODE_BODY, { status: 400 }));

      const res = await authClient.handler(
        postRequest("/auth/passkey/get-token", {
          authSession: DEFAULT.authSession,
          authResponse: MOCK_AUTH_RESPONSE,
          verification: { email: "000000" }
        })
      );

      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({
        error: "invalid_grant",
        error_description: "Invalid or expired session",
        is_retryable: true,
        auth_session: DEFAULT.authSession,
        verification_required: ["email"]
      });
    });

    it("get-token omits retry fields on a terminal error", async () => {
      mockToken(() =>
        HttpResponse.json(
          {
            error: "invalid_grant",
            error_description: "Invalid or expired session"
          },
          { status: 400 }
        )
      );

      const res = await authClient.handler(
        postRequest("/auth/passkey/get-token", {
          authSession: DEFAULT.authSession,
          authResponse: MOCK_AUTH_RESPONSE,
          verification: { email: "000000" }
        })
      );

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.is_retryable).toBe(false);
      expect(body).not.toHaveProperty("auth_session");
      expect(body).not.toHaveProperty("verification_required");
    });

    it("get-token returns 400 for an invalid verification key without calling Auth0", async () => {
      const bodies = mockToken(() => HttpResponse.json({}));

      const res = await authClient.handler(
        postRequest("/auth/passkey/get-token", {
          authSession: DEFAULT.authSession,
          authResponse: MOCK_AUTH_RESPONSE,
          verification: { phone_number: "123456" }
        })
      );

      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_request");
      expect(bodies).toHaveLength(0);
    });

    it("get-token returns 429 when rate limited", async () => {
      mockToken(() => new HttpResponse("Too Many Requests", { status: 429 }));

      const res = await authClient.handler(
        postRequest("/auth/passkey/get-token", {
          authSession: DEFAULT.authSession,
          authResponse: MOCK_AUTH_RESPONSE
        })
      );

      expect(res.status).toBe(429);
      expect((await res.json()).error).toBe("too_many_requests");
    });

    it("get-token returns 429 for a JSON access_denied rate limit", async () => {
      mockToken(() =>
        HttpResponse.json(
          { error: "access_denied", error_description: "Too Many Requests" },
          { status: 429 }
        )
      );

      const res = await authClient.handler(
        postRequest("/auth/passkey/get-token", {
          authSession: DEFAULT.authSession,
          authResponse: MOCK_AUTH_RESPONSE
        })
      );

      expect(res.status).toBe(429);
      expect((await res.json()).error).toBe("too_many_requests");
    });
  });
});
