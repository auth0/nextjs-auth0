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

import { serializeCredential } from "./index.js";

const BASE_URL = "http://localhost:3000";
const ENROLLMENT_CHALLENGE_URL = `${BASE_URL}/auth/passkey/enrollment-challenge`;
const ENROLLMENT_VERIFY_URL = `${BASE_URL}/auth/passkey/enrollment-verify`;
const REGISTER_URL = `${BASE_URL}/auth/passkey/register`;
const CHALLENGE_URL = `${BASE_URL}/auth/passkey/challenge`;
const VERIFY_URL = `${BASE_URL}/auth/passkey/get-token`;

const server = setupServer();

// Minimal fake credential with ALL optional ArrayBuffer fields present
function makeFakeFullCredential(): PublicKeyCredential {
  const encoder = new TextEncoder();
  const clientDataJSON = encoder.encode(
    JSON.stringify({ type: "webauthn.create", challenge: "Y2hhbGxlbmdl" })
  );
  const attestationObject = encoder.encode("fake-attestation");
  const authenticatorData = encoder.encode("fake-auth-data");
  const signature = encoder.encode("fake-signature");

  return {
    id: "credential-id",
    rawId: encoder.encode("credential-id").buffer,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: clientDataJSON.buffer,
      attestationObject: attestationObject.buffer,
      authenticatorData: authenticatorData.buffer,
      signature: signature.buffer,
      userHandle: encoder.encode("user-handle").buffer
    } as unknown as AuthenticatorAttestationResponse,
    getClientExtensionResults: () => ({ appid: true })
  } as unknown as PublicKeyCredential;
}

// Credential with no userHandle (null)
function makeFakeCredentialNullUserHandle(): PublicKeyCredential {
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
    authenticatorAttachment: null,
    response: {
      clientDataJSON: clientDataJSON.buffer,
      authenticatorData: authenticatorData.buffer,
      signature: signature.buffer,
      userHandle: null
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults: () => ({})
  } as unknown as PublicKeyCredential;
}

const FAKE_CHALLENGE_RESPONSE = {
  authSession: "fake-auth-session-token",
  authnParamsPublicKey: {
    challenge: "Y2hhbGxlbmdl",
    rp: { name: "Test App", id: "localhost" },
    user: {
      id: "dXNlcklk",
      name: "user@example.com",
      displayName: "Test User"
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    timeout: 60000,
    excludeCredentials: [{ id: "ZXhjbHVkZWQ", type: "public-key" }],
    authenticatorSelection: { residentKey: "required" },
    attestation: "none"
  }
};

const FAKE_LOGIN_CHALLENGE_RESPONSE = {
  authSession: "fake-auth-session-token",
  authnParamsPublicKey: {
    challenge: "Y2hhbGxlbmdl",
    rpId: "localhost",
    allowCredentials: [{ id: "YWxsb3dlZA", type: "public-key" }],
    timeout: 60000,
    userVerification: "required"
  }
};

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });

  process.env.NEXT_PUBLIC_PASSKEY_REGISTER_ROUTE = REGISTER_URL;
  process.env.NEXT_PUBLIC_PASSKEY_CHALLENGE_ROUTE = CHALLENGE_URL;
  process.env.NEXT_PUBLIC_PASSKEY_GET_TOKEN_ROUTE = VERIFY_URL;
  process.env.NEXT_PUBLIC_PASSKEY_ENROLLMENT_CHALLENGE_ROUTE =
    ENROLLMENT_CHALLENGE_URL;
  process.env.NEXT_PUBLIC_PASSKEY_ENROLLMENT_VERIFY_ROUTE =
    ENROLLMENT_VERIFY_URL;

  if (!window.PublicKeyCredential) {
    Object.defineProperty(window, "PublicKeyCredential", {
      value: class PublicKeyCredential {},
      writable: true,
      configurable: true
    });
  }
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
  Object.defineProperty(navigator, "credentials", {
    value: { create: vi.fn(), get: vi.fn() },
    writable: true,
    configurable: true
  });
});

afterAll(() => {
  delete process.env.NEXT_PUBLIC_PASSKEY_REGISTER_ROUTE;
  delete process.env.NEXT_PUBLIC_PASSKEY_CHALLENGE_ROUTE;
  delete process.env.NEXT_PUBLIC_PASSKEY_GET_TOKEN_ROUTE;
  delete process.env.NEXT_PUBLIC_PASSKEY_ENROLLMENT_CHALLENGE_ROUTE;
  delete process.env.NEXT_PUBLIC_PASSKEY_ENROLLMENT_VERIFY_ROUTE;
  server.close();
});

// ============================================================================
// serializeCredential — exported helper, test directly
// ============================================================================

describe("serializeCredential", () => {
  it("serialises all ArrayBuffer fields to base64url strings with optional fields present", () => {
    const credential = makeFakeFullCredential();
    const result = serializeCredential(credential);

    expect(result.id).toBe("credential-id");
    expect(typeof result.rawId).toBe("string");
    expect(result.type).toBe("public-key");
    expect(result.authenticatorAttachment).toBe("platform");
    expect(typeof result.response.clientDataJSON).toBe("string");
    expect(typeof result.response.attestationObject).toBe("string");
    expect(typeof result.response.authenticatorData).toBe("string");
    expect(typeof result.response.signature).toBe("string");
    // userHandle is a non-null buffer → should be base64url string
    expect(typeof result.response.userHandle).toBe("string");
    expect(result.clientExtensionResults).toEqual({ appid: true });
  });

  it("serialises credential with null userHandle correctly", () => {
    const credential = makeFakeCredentialNullUserHandle();
    const result = serializeCredential(credential);

    expect(result.authenticatorAttachment).toBeNull();
    expect(result.response.userHandle).toBeNull();
  });

  it("omits attestationObject when not present in response", () => {
    const encoder = new TextEncoder();
    const cred = {
      id: "cred-id",
      rawId: encoder.encode("cred-id").buffer,
      type: "public-key",
      authenticatorAttachment: undefined,
      response: {
        clientDataJSON: encoder.encode("data").buffer
        // no attestationObject, no authenticatorData, no signature, no userHandle
      },
      getClientExtensionResults: () => ({})
    } as unknown as PublicKeyCredential;

    const result = serializeCredential(cred);
    expect(result.response.attestationObject).toBeUndefined();
    expect(result.response.authenticatorData).toBeUndefined();
    expect(result.response.signature).toBeUndefined();
    expect(result.response.userHandle).toBeUndefined();
    expect(result.authenticatorAttachment).toBeNull();
  });
});

// ============================================================================
// ClientPasskeyClient unit tests
// ============================================================================

describe("ClientPasskeyClient unit", () => {
  let client: typeof import("./index.js").passkey;

  beforeEach(async () => {
    const mod = await import("./index.js");
    client = mod.passkey;
  });

  // -------------------------------------------------------------------------
  // assertWebAuthnSupported
  // -------------------------------------------------------------------------

  describe("assertWebAuthnSupported", () => {
    it("throws PasskeyGetTokenError when PublicKeyCredential is not available", async () => {
      // Remove PublicKeyCredential from window to simulate unsupported browser
      const orig = window.PublicKeyCredential;
      Object.defineProperty(window, "PublicKeyCredential", {
        value: undefined,
        writable: true,
        configurable: true
      });

      const err = await client.signup().catch((e) => e);

      expect(err.name).toBe("PasskeyGetTokenError");
      expect(err.error).toBe("webauthn_not_supported");

      Object.defineProperty(window, "PublicKeyCredential", {
        value: orig,
        writable: true,
        configurable: true
      });
    });
  });

  // -------------------------------------------------------------------------
  // signup — decodeCreationOptions with excludeCredentials items
  // -------------------------------------------------------------------------

  describe("signup with excludeCredentials", () => {
    it("decodes excludeCredentials array buffers during challenge", async () => {
      server.use(
        http.post(REGISTER_URL, () =>
          HttpResponse.json(FAKE_CHALLENGE_RESPONSE)
        ),
        http.post(VERIFY_URL, () => HttpResponse.json({ success: true }))
      );

      vi.spyOn(navigator.credentials, "create").mockResolvedValue(
        makeFakeFullCredential()
      );

      // Should not throw — excludeCredentials items with ids are decoded
      await client.signup({ email: "user@example.com" });

      const callArg = (navigator.credentials.create as any).mock.calls[0][0];
      expect(callArg.publicKey.excludeCredentials[0].id).toBeInstanceOf(
        ArrayBuffer
      );
    });
  });

  // -------------------------------------------------------------------------
  // login — decodeRequestOptions with allowCredentials items
  // -------------------------------------------------------------------------

  describe("login with allowCredentials", () => {
    it("decodes allowCredentials array buffers during challenge", async () => {
      server.use(
        http.post(CHALLENGE_URL, () =>
          HttpResponse.json(FAKE_LOGIN_CHALLENGE_RESPONSE)
        ),
        http.post(VERIFY_URL, () => HttpResponse.json({ success: true }))
      );

      vi.spyOn(navigator.credentials, "get").mockResolvedValue(
        makeFakeCredentialNullUserHandle()
      );

      await client.login();

      const callArg = (navigator.credentials.get as any).mock.calls[0][0];
      expect(callArg.publicKey.allowCredentials[0].id).toBeInstanceOf(
        ArrayBuffer
      );
    });
  });

  // -------------------------------------------------------------------------
  // enrollmentVerify
  // -------------------------------------------------------------------------

  describe("enrollmentVerify", () => {
    it("posts to the enrollment verify route and returns the response", async () => {
      let capturedBody: Record<string, unknown> = {};
      const fakeResponse = {
        authenticationMethodId: "amr-id-123",
        status: "enrolled"
      };

      server.use(
        http.post(ENROLLMENT_VERIFY_URL, async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(fakeResponse);
        })
      );

      const result = await client.enrollmentVerify({
        authenticationMethodId: "amr-id-123",
        authSession: "session-token",
        authResponse: serializeCredential(makeFakeFullCredential())
      });

      expect(capturedBody.authenticationMethodId).toBe("amr-id-123");
      expect(capturedBody.authSession).toBe("session-token");
      expect(result).toMatchObject(fakeResponse);
    });

    it("throws PasskeyEnrollmentVerifyError when the server returns an error", async () => {
      server.use(
        http.post(ENROLLMENT_VERIFY_URL, () =>
          HttpResponse.json(
            {
              error: "invalid_grant",
              error_description: "Enrollment verification failed."
            },
            { status: 400 }
          )
        )
      );

      const err = await client
        .enrollmentVerify({
          authenticationMethodId: "amr-id-123",
          authSession: "session-token",
          authResponse: serializeCredential(makeFakeFullCredential())
        })
        .catch((e) => e);

      expect(err.name).toBe("PasskeyEnrollmentVerifyError");
      expect(err.error).toBe("invalid_grant");
    });

    it("throws PasskeyEnrollmentVerifyError on network failure", async () => {
      server.use(http.post(ENROLLMENT_VERIFY_URL, () => HttpResponse.error()));

      const err = await client
        .enrollmentVerify({
          authenticationMethodId: "amr-id-123",
          authSession: "session-token",
          authResponse: serializeCredential(makeFakeFullCredential())
        })
        .catch((e) => e);

      expect(err.name).toBe("PasskeyEnrollmentVerifyError");
      // Network error gives no .error property on the caught fetch TypeError,
      // so the catch block falls back to "unknown_error"
      expect(err.error).toBe("unknown_error");
    });
  });

  // -------------------------------------------------------------------------
  // _verify — err?.error is undefined → falls back to "client_error"
  // -------------------------------------------------------------------------

  describe("_verify fallback error code", () => {
    it("throws PasskeyGetTokenError with client_error when verify response has no .error field", async () => {
      server.use(
        http.post(REGISTER_URL, () =>
          HttpResponse.json(FAKE_CHALLENGE_RESPONSE)
        ),
        // Return a non-ok response with no `error` field
        http.post(VERIFY_URL, () =>
          HttpResponse.json(
            { message: "Something went wrong" },
            { status: 500 }
          )
        )
      );

      vi.spyOn(navigator.credentials, "create").mockResolvedValue(
        makeFakeFullCredential()
      );

      const err = await client
        .signup({ email: "user@example.com" })
        .catch((e) => e);

      expect(err.name).toBe("PasskeyGetTokenError");
      expect(err.error).toBe("client_error");
    });
  });

  // -------------------------------------------------------------------------
  // enrollmentChallenge — non-mfa_required error path
  // -------------------------------------------------------------------------

  describe("enrollmentChallenge non-mfa error", () => {
    it("throws PasskeyEnrollmentChallengeError for non-mfa_required errors", async () => {
      server.use(
        http.post(ENROLLMENT_CHALLENGE_URL, () =>
          HttpResponse.json(
            {
              error: "insufficient_scope",
              error_description: "Missing authentication method."
            },
            { status: 403 }
          )
        )
      );

      const err = await client.enrollmentChallenge().catch((e) => e);

      expect(err.name).toBe("PasskeyEnrollmentChallengeError");
      expect(err.error).toBe("insufficient_scope");
    });
  });
});
