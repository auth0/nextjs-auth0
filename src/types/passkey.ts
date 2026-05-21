/**
 * Passkey (WebAuthn) types for authentication and enrollment flows.
 *
 * Response types use snake_case to match Auth0 API conventions.
 * SDK-facing types use camelCase.
 */

/**
 * Grant type for passkey (WebAuthn) token exchange.
 * Used in the /oauth/token request after a successful passkey assertion.
 */
export const GRANT_TYPE_PASSKEY = "urn:okta:params:oauth:grant-type:webauthn";

// ---------------------------------------------------------------------------
// Challenge request options
// ---------------------------------------------------------------------------

/**
 * Options for requesting a passkey signup challenge.
 * Triggers Auth0 POST /passkey/register.
 */
export interface PasskeySignupChallengeOptions {
  /**
   * User display name shown in the browser's passkey dialog.
   * Typically the user's name or email address.
   */
  userDisplayName?: string;
}

/**
 * Options for requesting a passkey login challenge.
 * Triggers Auth0 POST /passkey/challenge.
 */
export interface PasskeyLoginChallengeOptions {
  /**
   * Auth0 username or email — narrows the credential list in the browser
   * passkey picker. Optional: omit for a discoverable credentials flow.
   */
  username?: string;
}

// ---------------------------------------------------------------------------
// Challenge response
// ---------------------------------------------------------------------------

/**
 * Response from Auth0 after a signup or login challenge request.
 * `authnParamsPublicKey` is passed verbatim to `navigator.credentials.create()`
 * (signup) or `navigator.credentials.get()` (login).
 *
 * @example
 * ```typescript
 * const challenge = await auth0.passkey.signupChallenge();
 * const credential = await navigator.credentials.create({
 *   publicKey: challenge.authnParamsPublicKey
 * });
 * await auth0.passkey.verify({ authSession: challenge.authSession, authResponse: credential });
 * ```
 */
export interface PasskeyChallengeResponse {
  /** Flow state token — must be echoed back in the verify call. */
  authSession: string;
  /**
   * WebAuthn PublicKeyCredentialCreationOptions (signup) or
   * PublicKeyCredentialRequestOptions (login) from Auth0.
   * Pass directly to `navigator.credentials.create()` or `.get()`.
   */
  authnParamsPublicKey: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Verify (token exchange)
// ---------------------------------------------------------------------------

/**
 * Serialised form of the `PublicKeyCredential` returned by
 * `navigator.credentials.create()` or `navigator.credentials.get()`.
 *
 * All `ArrayBuffer` fields are base64url-encoded strings so they can be
 * JSON-serialised and sent to the server.
 */
export interface PasskeyAuthResponse {
  /** Base64url-encoded credential ID. */
  id: string;
  /** Base64url-encoded raw credential ID bytes. */
  rawId: string;
  /** Credential type — always `"public-key"`. */
  type: "public-key";
  /** Authenticator response object (attestation or assertion). */
  response: {
    /** Base64url-encoded clientDataJSON. */
    clientDataJSON: string;
    /** Base64url-encoded attestationObject (create only). */
    attestationObject?: string;
    /** Base64url-encoded authenticatorData (get only). */
    authenticatorData?: string;
    /** Base64url-encoded signature (get only). */
    signature?: string;
    /** Base64url-encoded user handle (get only, may be null). */
    userHandle?: string | null;
  };
  /** Extensions output (optional). */
  extensions?: Record<string, unknown>;
}

/**
 * Options for completing a passkey authentication flow (signup or login).
 * Combines the `auth_session` from the challenge with the serialised
 * credential from the WebAuthn ceremony.
 */
export interface PasskeyVerifyOptions {
  /** Flow state token returned by the challenge call. */
  authSession: string;
  /** Serialised credential from `navigator.credentials.create/get()`. */
  authResponse: PasskeyAuthResponse;
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

/**
 * Response from Auth0 after requesting a passkey enrollment challenge.
 * The `authenticationMethodId` is extracted from the `Location` response header
 * and is required for the subsequent `enrollVerify` call.
 */
export interface PasskeyEnrollmentChallengeResponse {
  /** ID extracted from the `Location` header — needed for `enrollVerify`. */
  authenticationMethodId: string;
  /** Flow state token — must be echoed back in `enrollVerify`. */
  authSession: string;
  /**
   * WebAuthn PublicKeyCredentialCreationOptions from Auth0.
   * Pass directly to `navigator.credentials.create()`.
   */
  authnParamsPublicKey: Record<string, unknown>;
}

/**
 * Options for verifying a passkey enrollment.
 */
export interface PasskeyEnrollVerifyOptions {
  /** Authentication method ID from the enrollment challenge `Location` header. */
  authenticationMethodId: string;
  /** Flow state token from the enrollment challenge response. */
  authSession: string;
  /** Serialised attestation credential from `navigator.credentials.create()`. */
  authResponse: PasskeyAuthResponse;
}

// ---------------------------------------------------------------------------
// Enrollment result
// ---------------------------------------------------------------------------

/**
 * A registered passkey authentication method on the user's account.
 * Returned by `enrollVerify` on success.
 */
export interface PasskeyAuthenticationMethod {
  /** Authentication method ID. */
  id: string;
  /** Method type — always `"passkey"` for passkey methods. */
  type: string;
  /** User-visible name for the passkey (e.g., device name). */
  name?: string;
  /** ISO 8601 timestamp when the passkey was created. */
  createdAt?: string;
  /** ISO 8601 timestamp of the last time this passkey was used. */
  lastAuthenticatedAt?: string;
}

// ---------------------------------------------------------------------------
// PasskeyClient interface
// ---------------------------------------------------------------------------

/**
 * Passkey client interface exposed on the `auth0` server-side singleton
 * and as `passkey` on the client-side singleton.
 *
 * Authentication flow (signup / login):
 * 1. Call `signupChallenge()` or `loginChallenge()` to get the WebAuthn options.
 * 2. Pass `authnParamsPublicKey` to the browser WebAuthn API.
 * 3. Call `verify()` with `authSession` + serialised credential to exchange for a session.
 *
 * Enrollment flow (add passkey to existing account):
 * 1. Call `enrollmentChallenge()` to get the WebAuthn creation options.
 * 2. Pass `authnParamsPublicKey` to `navigator.credentials.create()`.
 * 3. Call `enrollVerify()` with `authenticationMethodId` + `authSession` + credential.
 */
export interface PasskeyClient {
  /**
   * Request a WebAuthn credential creation challenge for a new user signup.
   * Calls Auth0 `POST /passkey/register`.
   *
   * @param options - Optional display name for the new user.
   * @returns Challenge with `authSession` and `authnParamsPublicKey`.
   */
  signupChallenge(
    options?: PasskeySignupChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  /**
   * Request a WebAuthn credential assertion challenge for login.
   * Calls Auth0 `POST /passkey/challenge`.
   *
   * @param options - Optional username to narrow the credential list.
   * @returns Challenge with `authSession` and `authnParamsPublicKey`.
   */
  loginChallenge(
    options?: PasskeyLoginChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  /**
   * Complete a passkey signup or login by exchanging the WebAuthn assertion
   * for an Auth0 session. Calls Auth0 `POST /oauth/token` with the WebAuthn grant.
   *
   * @param options - `authSession` from the challenge + serialised credential.
   */
  verify(options: PasskeyVerifyOptions): Promise<void>;

  /**
   * Request a WebAuthn credential creation challenge for enrolling a new passkey
   * on an existing authenticated account. Calls Auth0 MyAccount API
   * `POST /me/v1/authentication-methods`.
   *
   * @returns Challenge with `authenticationMethodId`, `authSession`, and `authnParamsPublicKey`.
   */
  enrollmentChallenge(): Promise<PasskeyEnrollmentChallengeResponse>;

  /**
   * Complete a passkey enrollment by verifying the newly created credential.
   * Calls Auth0 MyAccount API `POST /me/v1/authentication-methods/{id}/verify`.
   *
   * @param options - `authenticationMethodId` + `authSession` + serialised credential.
   * @returns The registered passkey authentication method.
   */
  enrollVerify(
    options: PasskeyEnrollVerifyOptions
  ): Promise<PasskeyAuthenticationMethod>;
}
