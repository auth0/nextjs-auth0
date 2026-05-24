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
  userMetadata?: Record<string, unknown>;
  /** Auth0 database connection name. */
  connection?: string;
  /** Auth0 organization ID. */
  organization?: string;
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
  /** Auth0 database connection name. */
  connection?: string;
  /** Auth0 organization ID. */
  organization?: string;
}

// ---------------------------------------------------------------------------
// WebAuthn JSON-safe option shapes
// ---------------------------------------------------------------------------

/**
 * JSON-safe representation of a WebAuthn credential descriptor.
 * Binary fields are Base64URL-encoded strings (matching
 * `PublicKeyCredential.parseCreationOptionsFromJSON()` conventions).
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
 */
export interface PasskeyRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PasskeyCredentialDescriptorJSON[];
  userVerification?: string;
  extensions?: Record<string, unknown>;
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
 * const challenge = await auth0.passkey.signupChallenge({ email: 'user@example.com', name: 'Jane' });
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
   * WebAuthn credential creation options (signup) or request options (login)
   * from Auth0. Pass directly to `navigator.credentials.create()` or `.get()`.
   * Binary fields are Base64URL-encoded strings.
   */
  authnParamsPublicKey: PasskeyCreationOptionsJSON | PasskeyRequestOptionsJSON;
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
  /** Auth0 database connection name. */
  connection?: string;
  /** Auth0 organization ID. */
  organization?: string;
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

/**
 * Options for requesting a passkey enrollment challenge.
 * Triggers Auth0 MyAccount POST /me/v1/authentication-methods.
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
 * and is required for the subsequent `enrollVerify` call.
 */
export interface PasskeyEnrollmentChallengeResponse {
  /** ID extracted from the `Location` header — needed for `enrollVerify`. */
  authenticationMethodId: string;
  /** Flow state token — must be echoed back in `enrollVerify`. */
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
 * Field names match the Auth0 MyAccount API wire format (snake_case).
 */
export interface PasskeyAuthenticationMethod {
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
// PasskeyClient interface
// ---------------------------------------------------------------------------

/**
 * Server-side passkey interface — individual step methods for authentication flows.
 * Used by `auth0.passkey` on the server singleton.
 * Each method maps directly to one Auth0 API call.
 */
export interface PasskeyClient {
  /**
   * Request a WebAuthn credential creation challenge for a new user signup.
   * Calls Auth0 `POST /passkey/register`.
   *
   * @param options - User profile and optional connection/organization.
   * @returns Challenge with `authSession` and `authnParamsPublicKey`.
   */
  signupChallenge(
    options?: PasskeySignupChallengeOptions
  ): Promise<PasskeyChallengeResponse>;

  /**
   * Request a WebAuthn credential assertion challenge for login.
   * Calls Auth0 `POST /passkey/challenge`.
   *
   * @param options - Optional username, connection, or organization.
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
}

/**
 * Browser-side passkey interface — extends server steps with one-call convenience methods.
 * Used by the `passkey` singleton exported from `@auth0/nextjs-auth0/client`.
 *
 * Each flow has both a **one-call method** and **individual steps** for full control:
 *
 * Authentication:
 * - One-call: `signup(options?)` / `login(options?)`
 * - Steps:    `signupChallenge()` → `navigator.credentials.create/get()` → `verify()`
 */
export interface PasskeyBrowserClient extends PasskeyClient {
  /**
   * Complete a full passkey signup in one call.
   * Fetches the challenge, runs `navigator.credentials.create()`, then verifies.
   *
   * @param options - User profile and optional connection/organization.
   */
  signup(options?: PasskeySignupChallengeOptions): Promise<void>;

  /**
   * Complete a full passkey login in one call.
   * Fetches the challenge, runs `navigator.credentials.get()`, then verifies.
   *
   * @param options - Optional username, connection, or organization.
   */
  login(options?: PasskeyLoginChallengeOptions): Promise<void>;
}
