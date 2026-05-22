// @vitest-environment jsdom
// @vitest-environment-options {"url": "http://localhost:3000"}
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

const BASE_URL = "http://localhost:3000";

const SIGNUP_CHALLENGE_URL = `${BASE_URL}/auth/passkey/signup-challenge`;
const LOGIN_CHALLENGE_URL = `${BASE_URL}/auth/passkey/login-challenge`;
const VERIFY_URL = `${BASE_URL}/auth/passkey/verify`;

// Minimal fake challenge payload returned by the SDK route handler (camelCase —
// the handler transforms Auth0's snake_case response before returning JSON).
const FAKE_CHALLENGE_RESPONSE = {
  authSession: "fake-auth-session-token",
  authnParamsPublicKey: {
    challenge: "Y2hhbGxlbmdl", // base64url("challenge")
    rp: { name: "Test App", id: "localhost" },
    user: {
      id: "dXNlcklk", // base64url("userId")
      name: "user@example.com",
      displayName: "Test User"
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    timeout: 60000,
    excludeCredentials: [],
    authenticatorSelection: { residentKey: "required" },
    attestation: "none"
  }
};

// Minimal fake credential returned by navigator.credentials.create/get
function makeFakeCredential(): PublicKeyCredential {
  const encoder = new TextEncoder();
  const clientDataJSON = encoder.encode(
    JSON.stringify({ type: "webauthn.create", challenge: "Y2hhbGxlbmdl" })
  );
  const attestationObject = encoder.encode("fake-attestation");

  return {
    id: "credential-id",
    rawId: encoder.encode("credential-id").buffer,
    type: "public-key",
    response: {
      clientDataJSON: clientDataJSON.buffer,
      attestationObject: attestationObject.buffer
    } as AuthenticatorAttestationResponse,
    getClientExtensionResults: () => ({})
  } as unknown as PublicKeyCredential;
}

function makeFakeAssertionCredential(): PublicKeyCredential {
  const encoder = new TextEncoder();
  const clientDataJSON = encoder.encode(
    JSON.stringify({ type: "webauthn.get", challenge: "Y2hhbGxlbmdl" })
  );
  const authenticatorData = encoder.encode("fake-auth-data");
  const signature = encoder.encode("fake-signature");

  return {
    id: "credential-id",
    rawId: encoder.encode("credential-id").buffer,
    type: "public-key",
    response: {
      clientDataJSON: clientDataJSON.buffer,
      authenticatorData: authenticatorData.buffer,
      signature: signature.buffer,
      userHandle: null
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults: () => ({})
  } as unknown as PublicKeyCredential;
}

const server = setupServer();

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });

  process.env.NEXT_PUBLIC_PASSKEY_SIGNUP_CHALLENGE_ROUTE = SIGNUP_CHALLENGE_URL;
  process.env.NEXT_PUBLIC_PASSKEY_LOGIN_CHALLENGE_ROUTE = LOGIN_CHALLENGE_URL;
  process.env.NEXT_PUBLIC_PASSKEY_VERIFY_ROUTE = VERIFY_URL;

  // jsdom does not implement navigator.credentials — define a stub so vi.spyOn works
  if (!navigator.credentials) {
    Object.defineProperty(navigator, "credentials", {
      value: { create: vi.fn(), get: vi.fn() },
      writable: true,
      configurable: true
    });
  }
});

afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
  // Re-stub navigator.credentials after restoreAllMocks wipes it
  Object.defineProperty(navigator, "credentials", {
    value: { create: vi.fn(), get: vi.fn() },
    writable: true,
    configurable: true
  });
});

afterAll(() => {
  delete process.env.NEXT_PUBLIC_PASSKEY_SIGNUP_CHALLENGE_ROUTE;
  delete process.env.NEXT_PUBLIC_PASSKEY_LOGIN_CHALLENGE_ROUTE;
  delete process.env.NEXT_PUBLIC_PASSKEY_VERIFY_ROUTE;
  server.close();
});

describe("ClientPasskeyClient", () => {
  let client: typeof import("./index.js").passkey;

  beforeEach(async () => {
    const mod = await import("./index.js");
    client = mod.passkey;
  });

  // ---------------------------------------------------------------------------
  // signup()
  // ---------------------------------------------------------------------------

  describe("signup", () => {
    it("requests signup challenge, calls credentials.create, then posts to verify", async () => {
      let capturedChallengeBody: Record<string, unknown> = {};
      let capturedVerifyBody: Record<string, unknown> = {};

      server.use(
        http.post(SIGNUP_CHALLENGE_URL, async ({ request }) => {
          capturedChallengeBody = (await request.json()) as Record<
            string,
            unknown
          >;
          return HttpResponse.json(FAKE_CHALLENGE_RESPONSE);
        }),
        http.post(VERIFY_URL, async ({ request }) => {
          capturedVerifyBody = (await request.json()) as Record<
            string,
            unknown
          >;
          return HttpResponse.json({ success: true });
        })
      );

      vi.spyOn(navigator.credentials, "create").mockResolvedValue(
        makeFakeCredential()
      );

      await client.signup({ email: "user@example.com", name: "Test User" });

      expect(capturedChallengeBody).toMatchObject({
        email: "user@example.com",
        name: "Test User"
      });
      expect(navigator.credentials.create).toHaveBeenCalledOnce();
      expect(capturedVerifyBody).toMatchObject({
        authSession: FAKE_CHALLENGE_RESPONSE.authSession
      });
      expect(capturedVerifyBody.authResponse).toBeDefined();
    });

    it("passes empty body when no options provided", async () => {
      let capturedChallengeBody: unknown = undefined;

      server.use(
        http.post(SIGNUP_CHALLENGE_URL, async ({ request }) => {
          capturedChallengeBody = await request.json();
          return HttpResponse.json(FAKE_CHALLENGE_RESPONSE);
        }),
        http.post(VERIFY_URL, () => HttpResponse.json({ success: true }))
      );

      vi.spyOn(navigator.credentials, "create").mockResolvedValue(
        makeFakeCredential()
      );

      await client.signup();

      expect(capturedChallengeBody).toEqual({});
    });

    it("throws PasskeySignupChallengeError when challenge request fails", async () => {
      server.use(
        http.post(SIGNUP_CHALLENGE_URL, () =>
          HttpResponse.json(
            {
              error: "passkeys_not_enabled",
              error_description:
                "Passkeys are not enabled for this application."
            },
            { status: 400 }
          )
        )
      );

      const err = await client.signup().catch((e) => e);

      expect(err.name).toBe("PasskeySignupChallengeError");
      expect(err.error).toBe("passkeys_not_enabled");
      expect(err.error_description).toBe(
        "Passkeys are not enabled for this application."
      );
    });

    it("throws PasskeySignupChallengeError on network failure during challenge", async () => {
      server.use(http.post(SIGNUP_CHALLENGE_URL, () => HttpResponse.error()));

      const err = await client.signup().catch((e) => e);

      expect(err.name).toBe("PasskeySignupChallengeError");
      expect(err.error).toBe("client_error");
    });

    it("throws PasskeyVerifyError when navigator.credentials.create throws", async () => {
      server.use(
        http.post(SIGNUP_CHALLENGE_URL, () =>
          HttpResponse.json(FAKE_CHALLENGE_RESPONSE)
        )
      );

      vi.spyOn(navigator.credentials, "create").mockRejectedValue(
        new DOMException("The operation was aborted.", "AbortError")
      );

      const err = await client.signup().catch((e) => e);

      expect(err.name).toBe("PasskeyVerifyError");
      expect(err.error).toBe("webauthn_error");
    });

    it("throws PasskeyVerifyError when credentials.create returns null", async () => {
      server.use(
        http.post(SIGNUP_CHALLENGE_URL, () =>
          HttpResponse.json(FAKE_CHALLENGE_RESPONSE)
        )
      );

      vi.spyOn(navigator.credentials, "create").mockResolvedValue(null);

      const err = await client.signup().catch((e) => e);

      expect(err.name).toBe("PasskeyVerifyError");
      expect(err.error).toBe("webauthn_error");
    });

    it("throws PasskeyVerifyError when verify route returns an error", async () => {
      server.use(
        http.post(SIGNUP_CHALLENGE_URL, () =>
          HttpResponse.json(FAKE_CHALLENGE_RESPONSE)
        ),
        http.post(VERIFY_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_grant",
              error_description: "Invalid passkey credential."
            },
            { status: 403 }
          )
        )
      );

      vi.spyOn(navigator.credentials, "create").mockResolvedValue(
        makeFakeCredential()
      );

      const err = await client.signup().catch((e) => e);

      expect(err.name).toBe("PasskeyVerifyError");
      expect(err.error).toBe("invalid_grant");
    });

    it("serialises credential ArrayBuffers as base64url strings", async () => {
      let capturedVerifyBody: Record<string, any> = {};

      server.use(
        http.post(SIGNUP_CHALLENGE_URL, () =>
          HttpResponse.json(FAKE_CHALLENGE_RESPONSE)
        ),
        http.post(VERIFY_URL, async ({ request }) => {
          capturedVerifyBody = (await request.json()) as Record<string, any>;
          return HttpResponse.json({ success: true });
        })
      );

      vi.spyOn(navigator.credentials, "create").mockResolvedValue(
        makeFakeCredential()
      );

      await client.signup();

      const authResponse = capturedVerifyBody.authResponse;
      expect(typeof authResponse.id).toBe("string");
      expect(typeof authResponse.rawId).toBe("string");
      expect(authResponse.type).toBe("public-key");
      expect(typeof authResponse.response.clientDataJSON).toBe("string");
      expect(typeof authResponse.response.attestationObject).toBe("string");
    });
  });

  // ---------------------------------------------------------------------------
  // login()
  // ---------------------------------------------------------------------------

  describe("login", () => {
    it("requests login challenge, calls credentials.get, then posts to verify", async () => {
      let capturedChallengeBody: Record<string, unknown> = {};
      let capturedVerifyBody: Record<string, unknown> = {};

      server.use(
        http.post(LOGIN_CHALLENGE_URL, async ({ request }) => {
          capturedChallengeBody = (await request.json()) as Record<
            string,
            unknown
          >;
          return HttpResponse.json(FAKE_CHALLENGE_RESPONSE);
        }),
        http.post(VERIFY_URL, async ({ request }) => {
          capturedVerifyBody = (await request.json()) as Record<
            string,
            unknown
          >;
          return HttpResponse.json({ success: true });
        })
      );

      vi.spyOn(navigator.credentials, "get").mockResolvedValue(
        makeFakeAssertionCredential()
      );

      await client.login({ username: "user@example.com" });

      expect(capturedChallengeBody).toMatchObject({
        username: "user@example.com"
      });
      expect(navigator.credentials.get).toHaveBeenCalledOnce();
      expect(capturedVerifyBody).toMatchObject({
        authSession: FAKE_CHALLENGE_RESPONSE.authSession
      });
    });

    it("passes empty body when no options provided", async () => {
      let capturedChallengeBody: unknown = undefined;

      server.use(
        http.post(LOGIN_CHALLENGE_URL, async ({ request }) => {
          capturedChallengeBody = await request.json();
          return HttpResponse.json(FAKE_CHALLENGE_RESPONSE);
        }),
        http.post(VERIFY_URL, () => HttpResponse.json({ success: true }))
      );

      vi.spyOn(navigator.credentials, "get").mockResolvedValue(
        makeFakeAssertionCredential()
      );

      await client.login();

      expect(capturedChallengeBody).toEqual({});
    });

    it("throws PasskeyLoginChallengeError when challenge request fails", async () => {
      server.use(
        http.post(LOGIN_CHALLENGE_URL, () =>
          HttpResponse.json(
            {
              error: "no_passkey_registered",
              error_description: "No passkey registered for this user."
            },
            { status: 400 }
          )
        )
      );

      const err = await client.login().catch((e) => e);

      expect(err.name).toBe("PasskeyLoginChallengeError");
      expect(err.error).toBe("no_passkey_registered");
    });

    it("throws PasskeyLoginChallengeError on network failure during challenge", async () => {
      server.use(http.post(LOGIN_CHALLENGE_URL, () => HttpResponse.error()));

      const err = await client.login().catch((e) => e);

      expect(err.name).toBe("PasskeyLoginChallengeError");
      expect(err.error).toBe("client_error");
    });

    it("throws PasskeyVerifyError when navigator.credentials.get throws", async () => {
      server.use(
        http.post(LOGIN_CHALLENGE_URL, () =>
          HttpResponse.json(FAKE_CHALLENGE_RESPONSE)
        )
      );

      vi.spyOn(navigator.credentials, "get").mockRejectedValue(
        new DOMException("NotAllowedError")
      );

      const err = await client.login().catch((e) => e);

      expect(err.name).toBe("PasskeyVerifyError");
      expect(err.error).toBe("webauthn_error");
    });

    it("throws PasskeyVerifyError when credentials.get returns null", async () => {
      server.use(
        http.post(LOGIN_CHALLENGE_URL, () =>
          HttpResponse.json(FAKE_CHALLENGE_RESPONSE)
        )
      );

      vi.spyOn(navigator.credentials, "get").mockResolvedValue(null);

      const err = await client.login().catch((e) => e);

      expect(err.name).toBe("PasskeyVerifyError");
      expect(err.error).toBe("webauthn_error");
    });

    it("serialises assertion credential ArrayBuffers as base64url strings", async () => {
      let capturedVerifyBody: Record<string, any> = {};

      server.use(
        http.post(LOGIN_CHALLENGE_URL, () =>
          HttpResponse.json(FAKE_CHALLENGE_RESPONSE)
        ),
        http.post(VERIFY_URL, async ({ request }) => {
          capturedVerifyBody = (await request.json()) as Record<string, any>;
          return HttpResponse.json({ success: true });
        })
      );

      vi.spyOn(navigator.credentials, "get").mockResolvedValue(
        makeFakeAssertionCredential()
      );

      await client.login();

      const authResponse = capturedVerifyBody.authResponse;
      expect(authResponse.type).toBe("public-key");
      expect(typeof authResponse.response.clientDataJSON).toBe("string");
      expect(typeof authResponse.response.authenticatorData).toBe("string");
      expect(typeof authResponse.response.signature).toBe("string");
      expect(authResponse.response.userHandle).toBeNull();
    });
  });
});
