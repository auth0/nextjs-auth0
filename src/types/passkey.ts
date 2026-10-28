/**
 * Passkey (WebAuthn) types for authentication and enrollment flows.
 *
 * SDK-facing types use camelCase. `PasskeyEnrollmentVerifyResponse` fields use
 * snake_case to match the Auth0 MyAccount API wire format.
 */

/**
 * Grant type for passkey (WebAuthn) token exchange.
 * Used in the /oauth/token request after a successful passkey assertion.
 *
 * @category Passkeys
 */
export const GRANT_TYPE_PASSKEY = "urn:okta:params:oauth:grant-type:webauthn";

// ---------------------------------------------------------------------------
// WebAuthn JSON-safe primitives
// ---------------------------------------------------------------------------

/**
 * JSON-safe representation of a WebAuthn credential descriptor.
 * Binary fields are Base64URL-encoded strings.
 *
 * @category Passkeys
 */
export interface PasskeyCredentialDescriptorJSON {
  id: string;
  type: "public-key";
  transports?: string[];
}

/**
 * JSON-safe WebAuthn credential creation options returned by Auth0 for signup
 * and enrollment flows. Pass directly to `navigator.credentials.create()`.
 * Binary fields (`challenge`, `user.id`, `excludeCredentials[].id`) are
 * Base64URL-encoded strings.
 *
 * @category Passkeys
 */
export interface PasskeyCreationOptionsJSON {
  challenge: string;
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout?: number;
  excludeCredentials?: PasskeyCredentialDescriptorJSON[];
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
  attestation?: string;
  extensions?: Record<string, unknown>;
}

/**
 * JSON-safe WebAuthn credential request options returned by Auth0 for login.
 * Pass directly to `navigator.credentials.get()`.
 * Binary fields (`challenge`, `allowCredentials[].id`) are Base64URL-encoded strings.
 *
 * @category Passkeys
 */
export interface PasskeyRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PasskeyCredentialDescriptorJSON[];
  userVerification?: string;
  extensions?: Record<string, unknown>;
}

/**
 * Serialised form of the `PublicKeyCredential` returned by
 * `navigator.credentials.create()` or `navigator.credentials.get()`.
 *
 * All `ArrayBuffer` fields are base64url-encoded strings so they can be
 * JSON-serialised and sent to the server.
 *
 * @category Passkeys
 */
export interface PasskeyAuthResponse {
  /** Base64url-encoded credential ID. */
  id: string;
  /** Base64url-encoded raw credential ID bytes. */
  rawId: string;
  /** Credential type — always `"public-key"`. */
  type: "public-key";
  /** How the authenticator is attached to the client (e.g. "platform", "cross-platform"). */
  authenticatorAttachment?: string | null;
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
  /** WebAuthn client extension results. */
  clientExtensionResults?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Identifier verification (signup)
// ---------------------------------------------------------------------------

/**
 * An identifier that Auth0 can ask the user to verify with a one-time code during passkey signup,
 * as listed in `verificationRequired`. The phone identifier is `'phone'`, not `'phoneNumber'`.
 */
export type PasskeyVerificationIdentifier = "email" | "phone";

/**
 * How Auth0 delivers the one-time code for the phone number during passkey signup: `'text'` (SMS) or `'voice'`.
 */
export type PasskeyDeliveryMethod = "text" | "voice";

/**
 * The one-time codes the user entered during passkey signup, keyed by identifier, for example
 * `{ email: '123456' }`. Pass them to `passkey.getToken()` as `verification`.
 */
export type PasskeyVerificationCodes = Partial<
  Record<PasskeyVerificationIdentifier, string>
>;

// ---------------------------------------------------------------------------
// Register flow (signup)
// ---------------------------------------------------------------------------

/**
 * Options for requesting a passkey signup challenge.
 * Triggers Auth0 POST /passkey/register.
 *
 * @category Passkeys
 */
export interface PasskeyRegisterOptions {
  /** User's email address. */
  email?: string;
  /** Username for the new account. */
  username?: string;
  /** User's phone number in E.164 format. */
  phoneNumber?: string;
  /** User's full name, shown in the browser passkey dialog. */
  name?: string;
  /** User's given (first) name. */
  givenName?: string;
  /** User's family (last) name. */
  familyName?: string;
  /** User's nickname. */
  nickname?: string;
  /** URL of the user's profile picture. */
  picture?: string;
  /** Additional user metadata. */
  userMetadata?: Record<string, string>;
  /** Auth0 database connection name. */
  connection?: string;
  /** Auth0 organization ID. */
  organization?: string;
  /**
   * Phone OTP delivery channel. Only relevant when the connection requires phone
   * identifier verification. Omit for email-only verification or when no
   * verification is required.
   */
  deliveryMethod?: PasskeyDeliveryMethod;
  /**
   * Browser `passkey.signup()` only; ignored by the server `register()`.
   *
   * Called when the connection requires identifier verification. Resolve with
   * the codes the user entered. It is called before the passkey is created,
   * and again with the remaining identifiers if a code is rejected. The same
   * passkey is resubmitted, so the user is not prompted for it twice.
   *
   * Without this callback a signup that requires verification fails with
   * `PasskeyGetTokenError` code `verification_required`.
   */
  onVerificationRequired?: (
    context: PasskeyVerificationContext
  ) => Promise<PasskeyVerificationCodes>;
}

/**
 * Response from Auth0 after a signup challenge request (POST /passkey/register).
 * `authnParamsPublicKey` is passed verbatim to `navigator.credentials.create()`.
 *
 * @example
 * ```typescript
 * const challenge = await auth0.passkey.register({ email: 'user@example.com', name: 'Jane' });
 * const credential = await navigator.credentials.create({
 *   publicKey: challenge.authnParamsPublicKey
 * });
 * await auth0.passkey.getToken({ authSession: challenge.authSession, authResponse: credential });
 * ```
 *
 * @category Passkeys
 */
export interface PasskeyRegisterResponse {
  /** Flow state token — must be echoed back in the getToken call. */
  authSession: string;
  /**
   * WebAuthn credential creation options from Auth0.
   * Pass directly to `navigator.credentials.create()`.
   * Binary fields are Base64URL-encoded strings.
   */
  authnParamsPublicKey: PasskeyCreationOptionsJSON;
  /**
   * Identifiers the user must verify with a one-time code before the passkey
   * is created, e.g. `["email"]`. Absent when no verification is required.
   * Pass the codes to `getToken()` as `verification`.
   */
  verificationRequired?: PasskeyVerificationIdentifier[];
}

// ---------------------------------------------------------------------------
// Challenge flow (login)
// ---------------------------------------------------------------------------

/**
 * Options for requesting a passkey login challenge.
 * Triggers Auth0 POST /passkey/challenge.
 *
 * @category Passkeys
 */
export interface PasskeyChallengeOptions {
  /** Auth0 database connection name. */
  connection?: string;
  /** Auth0 organization ID. */
  organization?: string;
}

/**
 * Response from Auth0 after a login challenge request (POST /passkey/challenge).
 *
 * @category Passkeys
 */
export interface PasskeyChallengeResponse {
  /** Flow state token — must be echoed back in the getToken call. */
  authSession: string;
  /**
   * WebAuthn credential request options from Auth0.
   * Pass directly to `navigator.credentials.get()`.
   * Binary fields are Base64URL-encoded strings.
   */
  authnParamsPublicKey: PasskeyRequestOptionsJSON;
}

// ---------------------------------------------------------------------------
// Token exchange (getToken)
// ---------------------------------------------------------------------------

/**
 * Options for completing a passkey authentication flow (signup or login).
 * Combines the `authSession` from the challenge with the serialised
 * credential from the WebAuthn ceremony.
 *
 * @category Passkeys
 */
export interface PasskeyGetTokenOptions {
  /** Flow state token returned by the challenge call. */
  authSession: string;
  /** Serialised credential from `navigator.credentials.create/get()`. */
  authResponse: PasskeyAuthResponse;
  /** Auth0 database connection name. */
  connection?: string;
  /** Auth0 organization ID. */
  organization?: string;
  /** Requested OAuth scopes (e.g. `"openid profile email"`). */
  scope?: string;
  /** Requested API audience. */
  audience?: string;
  /**
   * One-time codes for the identifiers in `verificationRequired`, signup only.
   * Keys must be `"email"` or `"phone"`.
   */
  verification?: PasskeyVerificationCodes;
}

// ---------------------------------------------------------------------------
// Enrollment flow
// ---------------------------------------------------------------------------

/**
 * Options for requesting a passkey enrollment challenge.
 * Triggers Auth0 MyAccount POST /me/v1/authentication-methods.
 *
 * @category Passkeys
 */
export interface PasskeyEnrollmentChallengeOptions {
  /**
   * Auth0 database connection name.
   * Required when the tenant has multiple database connections.
   */
  connection?: string;
  /**
   * Identity user ID to associate the passkey with a specific identity
   * when the user has multiple identities (linked accounts).
   */
  userIdentityId?: string;
}

/**
 * Response from Auth0 after requesting a passkey enrollment challenge.
 * The `authenticationMethodId` is extracted from the `Location` response header
 * and is required for the subsequent `enrollmentVerify` call.
 *
 * @category Passkeys
 */
export interface PasskeyEnrollmentChallengeResponse {
  /** ID extracted from the `Location` header — needed for `enrollmentVerify`. */
  authenticationMethodId: string;
  /** Flow state token — must be echoed back in `enrollmentVerify`. */
  authSession: string;
  /**
   * WebAuthn credential creation options from Auth0.
   * Pass directly to `navigator.credentials.create()`.
   * Binary fields are Base64URL-encoded strings.
   */
  authnParamsPublicKey: PasskeyCreationOptionsJSON;
}

/**
 * Options for verifying a passkey enrollment.
 * Triggers Auth0 MyAccount POST /me/v1/authentication-methods/{id}/verify.
 *
 * @category Passkeys
 */
export interface PasskeyEnrollmentVerifyOptions {
  /** Authentication method ID from the enrollment challenge `Location` header. */
  authenticationMethodId: string;
  /** Flow state token from the enrollment challenge response. */
  authSession: string;
  /** Serialised attestation credential from `navigator.credentials.create()`. */
  authResponse: PasskeyAuthResponse;
}

/**
 * A registered passkey authentication method on the user's account.
 * Returned by `enrollmentVerify` on success.
 * Field names match the Auth0 MyAccount API wire format (snake_case).
 *
 * @category Passkeys
 */
export interface PasskeyEnrollmentVerifyResponse {
  /** Authentication method ID. */
  id: string;
  /** Method type — always `"passkey"` for passkey methods. */
  type: "passkey";
  /** ISO 8601 timestamp when the passkey was created. */
  created_at?: string;
  /** Supported usage modes (e.g. "mfa", "passwordless"). */
  usage?: string[];
  /** The user identity this passkey belongs to. */
  identity_user_id?: string;
  /** Whether the credential is a multi-device credential. */
  credential_device_type?: string;
  /** Whether the credential is backed up to the cloud. */
  credential_backed_up?: boolean;
  /** Credential key ID. */
  key_id?: string;
  /** Base64url-encoded public key. */
  public_key?: string;
  /** Authenticator transports (e.g. "internal", "hybrid"). */
  transports?: string[];
  /** User agent of the device that enrolled the passkey. */
  user_agent?: string;
  /** Base64url-encoded user handle. */
  user_handle?: string;
  /** AAGUID of the authenticator. */
  aaguid?: string;
  /** Relying party ID (your Auth0 custom domain). */
  relying_party_id?: string;
}

// ---------------------------------------------------------------------------
// Browser signup options
// ---------------------------------------------------------------------------

/**
 * Context passed to `onVerificationRequired` during a browser passkey signup.
 */
export interface PasskeyVerificationContext {
  /** Identifiers that still need a one-time code. */
  verificationRequired: PasskeyVerificationIdentifier[];
  /** `true` when a previously entered code was rejected. */
  isRetry: boolean;
}

// ---------------------------------------------------------------------------
// Client interfaces
// ---------------------------------------------------------------------------

/**
 * Server-side passkey interface — individual step methods for authentication flows.
 * Used by `auth0.passkey` on the server singleton.
 * Each method maps directly to one Auth0 API call.
 *
 * @category Passkeys
 */
export interface PasskeyClient {
  /**
   * Request a WebAuthn credential creation challenge for a new user signup.
   * Calls Auth0 `POST /passkey/register`.
   *
   * When the connection requires the user's email address or phone number to be
   * verified, the response includes `verificationRequired` (for example
   * `['email', 'phone']`), and Auth0 sends a one-time code to each listed
   * identifier during this call. `verificationRequired` is absent when no
   * verification is required.
   *
   * `deliveryMethod` (`'text'` or `'voice'`) chooses how the phone code is
   * delivered. Leave it out to let Auth0 use the channel the connection supports
   * (SMS when it supports both or none). Auth0 rejects a channel that the
   * connection does not support with `invalid_request`.
   *
   * Every call starts a separate attempt with its own `authSession` and, when
   * verification is required, sends new codes. To recover from a wrong code,
   * retry `getToken()` instead of calling this again. Do not rely only on Auth0's
   * limits: rate-limit the route that calls this method yourself, per IP address
   * and per email address or phone number.
   *
   * @param options - User profile, optional connection/organization, and an optional `deliveryMethod` for the phone code.
   * @throws {PasskeyRegisterError} If there was an issue requesting the signup challenge, for example when a one-time code could not be sent.
   * @returns Challenge with `authSession` and `authnParamsPublicKey`.
   */
  register(options?: PasskeyRegisterOptions): Promise<PasskeyRegisterResponse>;

  /**
   * Request a WebAuthn credential assertion challenge for login.
   * Calls Auth0 `POST /passkey/challenge`.
   *
   * @param options - Optional connection or organization.
   * @returns Challenge with `authSession` and `authnParamsPublicKey`.
   */
  challenge(
    options?: PasskeyChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  /**
   * Complete a passkey signup or login by exchanging the WebAuthn assertion
   * for an Auth0 session. Calls Auth0 `POST /oauth/token` with the WebAuthn grant.
   * Session cookie is set automatically by the SDK.
   *
   * For a signup where `register()` returned `verificationRequired`, pass the codes
   * the user entered in `verification`, for example `{ email: '123456' }`. Omit it
   * otherwise, including on login.
   *
   * On a wrong code this throws a `PasskeyGetTokenError` whose `isRetryable` is
   * `true`, whose `authSession` is set and whose `verificationRequired` lists the
   * identifiers still needing a code. Call again with the same `authSession` and
   * credential, sending codes only for those identifiers.
   *
   * @param options - `authSession` from the challenge + serialised credential, and the `verification` codes when `register()` returned `verificationRequired`.
   * @throws {PasskeyGetTokenError} If there was an issue exchanging the credential for tokens. No session is persisted. When `isRetryable` is `true`, retry as described above. Otherwise the attempt is usually over, so start again with `register()` or `challenge()`. A temporary failure, such as rate limiting, can leave it open.
   */
  getToken(options: PasskeyGetTokenOptions): Promise<void>;

  /**
   * Request a WebAuthn credential creation challenge to enroll a new passkey
   * for the currently authenticated user.
   * Calls Auth0 MyAccount `POST /me/v1/authentication-methods`.
   * Requires an active session.
   */
  enrollmentChallenge(
    options?: PasskeyEnrollmentChallengeOptions
  ): Promise<PasskeyEnrollmentChallengeResponse>;

  /**
   * Complete a passkey enrollment by verifying the WebAuthn attestation.
   * Calls Auth0 MyAccount `POST /me/v1/authentication-methods/{id}/verify`.
   * Requires an active session.
   */
  enrollmentVerify(
    options: PasskeyEnrollmentVerifyOptions
  ): Promise<PasskeyEnrollmentVerifyResponse>;
}

/**
 * Browser-side passkey interface — one-call convenience methods.
 * Used by the `passkey` singleton exported from `@auth0/nextjs-auth0/client`.
 * Handles challenge fetch, WebAuthn ceremony, and token exchange internally.
 *
 * @category Passkeys
 */
export interface PasskeyBrowserClient {
  /**
   * Complete a full passkey signup in one call.
   * Fetches the challenge, collects any required verification codes, runs
   * `navigator.credentials.create()`, then exchanges for a session.
   *
   * @param options - User profile, optional connection/organization and
   * `onVerificationRequired` for connections that require identifier verification.
   */
  signup(options?: PasskeyRegisterOptions): Promise<void>;

  /**
   * Complete a full passkey login in one call.
   * Fetches the challenge, runs `navigator.credentials.get()`, then exchanges for a session.
   *
   * @param options - Optional connection or organization.
   */
  login(options?: PasskeyChallengeOptions): Promise<void>;

  /**
   * Request a passkey enrollment challenge for an already-authenticated user.
   * Calls Auth0 MyAccount `POST /me/v1/authentication-methods`.
   *
   * @param options - Optional connection or identity user ID.
   */
  enrollmentChallenge(
    options?: PasskeyEnrollmentChallengeOptions
  ): Promise<PasskeyEnrollmentChallengeResponse>;

  /**
   * Verify and complete a passkey enrollment.
   * Calls Auth0 MyAccount `POST /me/v1/authentication-methods/{id}/verify`.
   *
   * @param options - Authentication method ID, auth session, and serialised credential.
   */
  enrollmentVerify(
    options: PasskeyEnrollmentVerifyOptions
  ): Promise<PasskeyEnrollmentVerifyResponse>;
}
