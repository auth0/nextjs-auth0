import {
  PasskeyChallengeError,
  PasskeyEnrollmentChallengeError,
  PasskeyEnrollmentVerifyError,
  PasskeyGetTokenError,
  PasskeyRegisterError
} from "../../errors/index.js";
import type {
  PasskeyAuthResponse,
  PasskeyBrowserClient,
  PasskeyChallengeOptions,
  PasskeyChallengeResponse,
  PasskeyCreationOptionsJSON,
  PasskeyEnrollmentChallengeOptions,
  PasskeyEnrollmentChallengeResponse,
  PasskeyEnrollmentVerifyOptions,
  PasskeyEnrollmentVerifyResponse,
  PasskeyRegisterOptions,
  PasskeyRegisterResponse,
  PasskeyRequestOptionsJSON
} from "../../types/index.js";
import { normalizeWithBasePath } from "../../utils/pathUtils.js";

// ---------------------------------------------------------------------------
// base64url helpers (no external deps, works in all modern browsers)
// ---------------------------------------------------------------------------

function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64urlDecode(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (padded.length % 4)) % 4;
  const base64 = padded + "=".repeat(padding);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ---------------------------------------------------------------------------
// WebAuthn options normalisation
// Converts base64url-encoded strings from Auth0 back into ArrayBuffers
// so they can be passed to navigator.credentials.create/get.
// ---------------------------------------------------------------------------

function decodeCreationOptions(
  raw: PasskeyCreationOptionsJSON
): PublicKeyCredentialCreationOptions {
  const opts = raw as any;
  return {
    ...opts,
    challenge: base64urlDecode(opts.challenge),
    user: {
      ...opts.user,
      id: base64urlDecode(opts.user.id)
    },
    excludeCredentials: (opts.excludeCredentials ?? []).map((c: any) => ({
      ...c,
      id: base64urlDecode(c.id)
    }))
  };
}

function decodeRequestOptions(
  raw: PasskeyRequestOptionsJSON
): PublicKeyCredentialRequestOptions {
  const opts = raw as any;
  return {
    ...opts,
    challenge: base64urlDecode(opts.challenge),
    allowCredentials: (opts.allowCredentials ?? []).map((c: any) => ({
      ...c,
      id: base64urlDecode(c.id)
    }))
  };
}

// ---------------------------------------------------------------------------
// Serialise PublicKeyCredential → PasskeyAuthResponse
// Converts all ArrayBuffers back to base64url strings for JSON transport.
// ---------------------------------------------------------------------------

export function serializeCredential(
  credential: PublicKeyCredential
): PasskeyAuthResponse {
  const response = credential.response as any;
  return {
    id: credential.id,
    rawId: base64urlEncode(credential.rawId),
    type: "public-key",
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    response: {
      clientDataJSON: base64urlEncode(response.clientDataJSON),
      ...(response.attestationObject !== undefined && {
        attestationObject: base64urlEncode(response.attestationObject)
      }),
      ...(response.authenticatorData !== undefined && {
        authenticatorData: base64urlEncode(response.authenticatorData)
      }),
      ...(response.signature !== undefined && {
        signature: base64urlEncode(response.signature)
      }),
      ...(response.userHandle !== undefined && {
        userHandle: response.userHandle
          ? base64urlEncode(response.userHandle)
          : null
      })
    },
    clientExtensionResults: credential.getClientExtensionResults() as Record<
      string,
      unknown
    >
  };
}

// ---------------------------------------------------------------------------
// Fetch helpers
// ---------------------------------------------------------------------------

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({
      error: "client_error",
      error_description: "Failed to parse error response"
    }));
    return Promise.reject(err);
  }

  if (response.status === 204) {
    return undefined as unknown as T;
  }

  return response.json();
}

// ---------------------------------------------------------------------------
// ClientPasskeyClient
// ---------------------------------------------------------------------------

/**
 * Client-side passkey (WebAuthn) authentication singleton.
 *
 * Handles the signup and login flows — fetches the challenge from the SDK route
 * handler, calls navigator.credentials.create/get, then posts the serialised
 * credential back to the verify route to create a session.
 *
 * All ArrayBuffer ↔ base64url conversion is handled internally.
 *
 * @example Signup
 * ```typescript
 * 'use client';
 * import { passkey } from '@auth0/nextjs-auth0/client';
 *
 * await passkey.signup();
 * window.location.href = '/dashboard';
 * ```
 *
 * @example Login
 * ```typescript
 * 'use client';
 * import { passkey } from '@auth0/nextjs-auth0/client';
 *
 * await passkey.login();
 * window.location.href = '/dashboard';
 * ```
 *
 * @example Enroll a passkey for an existing user
 * ```typescript
 * 'use client';
 * import { passkey, serializeCredential } from '@auth0/nextjs-auth0/client';
 *
 * const challenge = await passkey.enrollmentChallenge();
 * const rawCredential = await navigator.credentials.create({ publicKey: challenge.authnParamsPublicKey });
 * await passkey.enrollmentVerify({
 *   authenticationMethodId: challenge.authenticationMethodId,
 *   authSession: challenge.authSession,
 *   authResponse: serializeCredential(rawCredential as PublicKeyCredential)
 * });
 * ```
 */
class ClientPasskeyClient implements PasskeyBrowserClient {
  private assertWebAuthnSupported(): void {
    if (
      typeof window === "undefined" ||
      !window.PublicKeyCredential ||
      typeof navigator?.credentials?.create !== "function" ||
      typeof navigator?.credentials?.get !== "function"
    ) {
      throw new PasskeyGetTokenError(
        "webauthn_not_supported",
        "WebAuthn is not supported in this browser",
        undefined
      );
    }
  }

  // ---------------------------------------------------------------------------
  // One-call convenience methods
  // ---------------------------------------------------------------------------

  /**
   * Complete a full passkey signup in one call.
   * Fetches the challenge, runs navigator.credentials.create(), then verifies.
   *
   * @throws {PasskeyGetTokenError} If WebAuthn is not supported in this browser
   * @throws {PasskeyRegisterError} If the challenge request fails
   * @throws {PasskeyGetTokenError} If the WebAuthn ceremony or token exchange fails
   */
  async signup(options?: PasskeyRegisterOptions): Promise<void> {
    this.assertWebAuthnSupported();
    const challengeUrl = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_PASSKEY_REGISTER_ROUTE || "/auth/passkey/register"
    );

    let challenge: PasskeyRegisterResponse;
    try {
      challenge = await postJson<PasskeyRegisterResponse>(
        challengeUrl,
        options ?? {}
      );
    } catch (err: any) {
      throw new PasskeyRegisterError(
        err?.error ?? "client_error",
        err?.error_description ?? "Failed to get passkey signup challenge",
        err?.error ? err : undefined
      );
    }

    let credential: PublicKeyCredential | null;
    try {
      credential = (await navigator.credentials.create({
        publicKey: decodeCreationOptions(
          challenge.authnParamsPublicKey as PasskeyCreationOptionsJSON
        )
      })) as PublicKeyCredential | null;
    } catch (err: any) {
      throw new PasskeyGetTokenError(
        "webauthn_error",
        err?.message ?? "WebAuthn credential creation failed",
        undefined
      );
    }

    if (!credential) {
      throw new PasskeyGetTokenError(
        "webauthn_error",
        "navigator.credentials.create returned null",
        undefined
      );
    }

    await this._verify(challenge.authSession, credential);
  }

  /**
   * Complete a full passkey login in one call.
   * Fetches the challenge, runs navigator.credentials.get(), then verifies.
   *
   * @throws {PasskeyGetTokenError} If WebAuthn is not supported in this browser
   * @throws {PasskeyChallengeError} If the challenge request fails
   * @throws {PasskeyGetTokenError} If the WebAuthn ceremony or token exchange fails
   */
  async login(options?: PasskeyChallengeOptions): Promise<void> {
    this.assertWebAuthnSupported();
    const challengeUrl = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_PASSKEY_CHALLENGE_ROUTE ||
        "/auth/passkey/challenge"
    );

    let challenge: PasskeyChallengeResponse;
    try {
      challenge = await postJson<PasskeyChallengeResponse>(
        challengeUrl,
        options ?? {}
      );
    } catch (err: any) {
      throw new PasskeyChallengeError(
        err?.error ?? "client_error",
        err?.error_description ?? "Failed to get passkey login challenge",
        err?.error ? err : undefined
      );
    }

    let credential: PublicKeyCredential | null;
    try {
      credential = (await navigator.credentials.get({
        publicKey: decodeRequestOptions(
          challenge.authnParamsPublicKey as PasskeyRequestOptionsJSON
        )
      })) as PublicKeyCredential | null;
    } catch (err: any) {
      throw new PasskeyGetTokenError(
        "webauthn_error",
        err?.message ?? "WebAuthn credential assertion failed",
        undefined
      );
    }

    if (!credential) {
      throw new PasskeyGetTokenError(
        "webauthn_error",
        "navigator.credentials.get returned null",
        undefined
      );
    }

    await this._verify(challenge.authSession, credential);
  }

  // Shared verify step used by both signup() and login()
  private async _verify(
    authSession: string,
    credential: PublicKeyCredential
  ): Promise<void> {
    const verifyUrl = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_PASSKEY_GET_TOKEN_ROUTE ||
        "/auth/passkey/get-token"
    );

    try {
      await postJson(verifyUrl, {
        authSession,
        authResponse: serializeCredential(credential)
      });
    } catch (err: any) {
      if (err?.error === "mfa_required") {
        throw err;
      }
      throw new PasskeyGetTokenError(
        err?.error ?? "client_error",
        err?.error_description ?? "Passkey verification failed",
        err?.error ? err : undefined
      );
    }
  }

  async enrollmentChallenge(
    options?: PasskeyEnrollmentChallengeOptions
  ): Promise<PasskeyEnrollmentChallengeResponse> {
    const challengeUrl = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_PASSKEY_ENROLLMENT_CHALLENGE_ROUTE ||
        "/auth/passkey/enrollment-challenge"
    );
    try {
      return await postJson<PasskeyEnrollmentChallengeResponse>(
        challengeUrl,
        options ?? {}
      );
    } catch (err: any) {
      if (err?.error === "mfa_required") {
        throw err;
      }
      throw new PasskeyEnrollmentChallengeError(
        err?.error ?? "unknown_error",
        err?.error_description ?? "Failed to get passkey enrollment challenge"
      );
    }
  }

  async enrollmentVerify(
    options: PasskeyEnrollmentVerifyOptions
  ): Promise<PasskeyEnrollmentVerifyResponse> {
    const verifyUrl = normalizeWithBasePath(
      process.env.NEXT_PUBLIC_PASSKEY_ENROLLMENT_VERIFY_ROUTE ||
        "/auth/passkey/enrollment-verify"
    );
    try {
      return await postJson<PasskeyEnrollmentVerifyResponse>(
        verifyUrl,
        options
      );
    } catch (err: any) {
      throw new PasskeyEnrollmentVerifyError(
        err?.error ?? "unknown_error",
        err?.error_description ?? "Passkey enrollment verification failed"
      );
    }
  }
}

/**
 * Client-side passkey (WebAuthn) singleton.
 *
 * @example
 * ```typescript
 * import { passkey } from '@auth0/nextjs-auth0/client';
 *
 * // One-call signup
 * await passkey.signup();
 *
 * // One-call login
 * await passkey.login();
 *
 * // Enroll a passkey for an authenticated user
 * const challenge = await passkey.enrollmentChallenge();
 * // ... run navigator.credentials.create() yourself ...
 * await passkey.enrollmentVerify({ authenticationMethodId: challenge.authenticationMethodId, authSession: challenge.authSession, authResponse: credential });
 * ```
 */
export const passkey: PasskeyBrowserClient = new ClientPasskeyClient();
