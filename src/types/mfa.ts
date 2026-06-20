/**
 * MFA-related types for authentication flow.
 *
 * Response types use snake_case to match Auth0 API conventions (consistent with SPA SDK).
 * SDK-facing types use camelCase.
 */

import type { MfaRequirements } from "../errors/index.js";

/**
 * Auth0 MFA API response types (snake_case).
 * These represent raw API responses before transformation to SDK types.
 */

/**
 * Authenticator response from Auth0 API (snake_case).
 * Maps to {@link Authenticator} in SDK-facing interface.
 */
export interface AuthenticatorApiResponse {
  /** Authenticator ID */
  id: string;
  /** Authenticator type (primary field) */
  authenticator_type: string;
  /** Direct type value (optional, feature-flagged field) */
  type?: string;
  /** Whether authenticator is active */
  active: boolean;
  /** Authenticator name (user-defined or default) */
  name?: string;
  /** Phone number for OOB (masked) */
  phone_number?: string;
  /** OOB channel (sms, voice) */
  oob_channel?: string;
  /** ISO 8601 timestamp of creation */
  created_at?: string;
  /** ISO 8601 timestamp of last authentication */
  last_auth?: string;
}

/**
 * Challenge response from Auth0 API (snake_case).
 * Maps to {@link ChallengeResponse} in SDK-facing interface.
 */
export interface ChallengeApiResponse {
  /** Challenge type (otp, oob) */
  challenge_type: string;
  /** OOB code (for oob challenges) */
  oob_code?: string;
  /** Binding method (for oob challenges) */
  binding_method?: string;
}

/**
 * Enrollment response from Auth0 API (snake_case).
 * Maps to {@link EnrollmentResponse} in SDK-facing interface.
 */
export interface EnrollmentApiResponse {
  /** Authenticator type discriminator */
  authenticator_type: "otp" | "oob" | "email";
  /** Authenticator ID */
  id: string;
  /** Recovery codes (first enrollment only) */
  recovery_codes?: string[];
  /** TOTP secret (otp only - required for otp) */
  secret?: string;
  /** Barcode URI (otp: otpauth:// format, oob: Guardian/Push QR code) */
  barcode_uri?: string;
  /** OOB channel (oob only - required for oob) */
  oob_channel?: "sms" | "voice" | "auth0" | "email";
  /** Authenticator name (oob/email only) */
  name?: string;
  /** OOB code (oob only - for enrollment verification) */
  oob_code?: string;
  /** Binding method (oob only - prompt, none) */
  binding_method?: string;
}

/**
 * Request body for verify endpoint (pre-validation).
 * Contains at least one verification credential.
 */
export interface VerifyCredentialBody {
  /** OTP code (6 digits) */
  otp?: string;
  /** OOB code from challenge */
  oobCode?: string;
  /** Binding code for OOB */
  bindingCode?: string;
  /** Recovery code */
  recoveryCode?: string;
}

/**
 * Grant type for MFA token exchange.
 * Used in token endpoint requests to exchange an mfa_token for access/refresh tokens.
 *
 * @see https://auth0.com/docs/api/authentication#verify-with-one-time-password-otp-
 */
export const GRANT_TYPE_MFA_OTP = "http://auth0.com/oauth/grant-type/mfa-otp";

/**
 * Grant type for MFA OOB (SMS/Email/Push) verification.
 *
 * @see https://auth0.com/docs/api/authentication#verify-with-oob
 */
export const GRANT_TYPE_MFA_OOB = "http://auth0.com/oauth/grant-type/mfa-oob";

/**
 * Grant type for MFA recovery code verification.
 *
 * @see https://auth0.com/docs/api/authentication#verify-with-recovery-code
 */
export const GRANT_TYPE_MFA_RECOVERY_CODE =
  "http://auth0.com/oauth/grant-type/mfa-recovery-code";

/**
 * MFA verify response.
 *
 * In Next.js (and any server-rendered app), tokens are stored in the session
 * cookie server-side after a successful verify. They are never sent in the HTTP
 * response body. Only `success: true` is guaranteed; call `getAccessToken()`
 * after verify to retrieve the access token.
 *
 * All fields other than `success` and `recovery_code` exist for backward
 * compatibility only and will always be `undefined` at runtime. They are
 * deprecated and will be removed in the next major version.
 *
 * @deprecated All token and metadata fields (`access_token`, `refresh_token`,
 * `scope`, `audience`, etc.) are deprecated. Use `getAccessToken()` after
 * `mfa.verify()` to retrieve the resulting token.
 */
export interface MfaVerifyResponse {
  /** Always `true` on a successful verification. */
  success: true;
  /**
   * @deprecated Always `undefined` — tokens are stored in the session cookie.
   * Use `getAccessToken()` instead.
   */
  access_token?: string;
  /**
   * @deprecated Always `undefined` — tokens are stored in the session cookie.
   */
  refresh_token?: string;
  /**
   * @deprecated Always `undefined` — tokens are stored in the session cookie.
   */
  id_token?: string;
  /**
   * @deprecated Always `undefined`.
   */
  token_type?: string;
  /**
   * @deprecated Always `undefined` — the caller already knows the requested scope.
   */
  scope?: string;
  /**
   * @deprecated Always `undefined` — the caller already knows the requested audience.
   */
  audience?: string;
  /**
   * @deprecated Always `undefined`.
   */
  expires_in?: number;
  /**
   * New recovery code, if the tenant regenerates it on verify.
   * Present only when a recovery code was used and the tenant is configured to rotate codes.
   */
  recovery_code?: string;
}

/**
 * Internal type for the raw Auth0 token endpoint response from MFA verification.
 * Used by server-internal methods (mfaVerify, cacheTokenFromMfaVerify) only.
 * Not exported as part of the public API.
 */
export interface MfaTokenEndpointResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  scope?: string;
  audience?: string;
  expires_in: number;
  recovery_code?: string;
}

/**
 * Factor types for MFA enrollment.
 */
export type FactorType = "otp" | "sms" | "voice" | "email" | "push";

/**
 * Enroll OTP authenticator using factorType.
 */
export interface EnrollFactorTypeOtpOptions {
  /** Encrypted MFA token */
  mfaToken: string;
  /** Factor type discriminator */
  factorType: "otp";
}

/**
 * Enroll OOB authenticator using factorType.
 */
export interface EnrollFactorTypeOobOptions {
  /** Encrypted MFA token */
  mfaToken: string;
  /** Factor type discriminator */
  factorType: "sms" | "voice" | "email" | "push";
  /** Phone number in E.164 format (required for sms/voice) */
  phoneNumber?: string;
  /** Email address (optional for email channel - uses user's email if not provided) */
  email?: string;
}

/**
 * Enroll OTP authenticator (TOTP app like Authy/Google Authenticator).
 */
export interface EnrollOtpOptions {
  /** Encrypted MFA token */
  mfaToken: string;
  /** Authenticator types to enroll */
  authenticatorTypes: ["otp"];
}

/**
 * Enroll OOB authenticator (SMS/Voice/Push/Email).
 */
export interface EnrollOobOptions {
  /** Encrypted MFA token */
  mfaToken: string;
  /** Authenticator types to enroll */
  authenticatorTypes: ["oob"];
  /** OOB channels (sms, voice, auth0, email) */
  oobChannels: ("sms" | "voice" | "auth0" | "email")[];
  /** Phone number in E.164 format (required for sms/voice) */
  phoneNumber?: string;
  /** Email address (optional for email channel - uses user's email if not provided) */
  email?: string;
}

/**
 * MFA enrollment options (discriminated union).
 */
export type EnrollOptions =
  | EnrollFactorTypeOtpOptions
  | EnrollFactorTypeOobOptions
  | EnrollOtpOptions
  | EnrollOobOptions;

/**
 * OTP enrollment response.
 */
export interface OtpEnrollmentResponse {
  /** Authenticator type discriminator */
  authenticatorType: "otp";
  /** TOTP secret (for QR code generation) */
  secret: string;
  /** Barcode URI (otpauth:// format) */
  barcodeUri: string;
  /** Recovery codes (first enrollment only) */
  recoveryCodes?: string[];
  /** Authenticator ID */
  id: string;
}

/**
 * OOB enrollment response (SMS/Voice/Push/Email).
 */
export interface OobEnrollmentResponse {
  /** Authenticator type discriminator */
  authenticatorType: "oob";
  /** OOB channel */
  oobChannel: "sms" | "voice" | "auth0" | "email";
  /** Recovery codes (first enrollment only) */
  recoveryCodes?: string[];
  /** Authenticator ID */
  id: string;
  /** Authenticator name */
  name?: string;
  /** OOB code for enrollment verification */
  oobCode?: string;
  /** Binding method (prompt, none) */
  bindingMethod?: string;
  /** Barcode URI (for Guardian/Push QR code) */
  barcodeUri?: string;
}

/**
 * MFA enrollment response (discriminated union).
 */
export type EnrollmentResponse = OtpEnrollmentResponse | OobEnrollmentResponse;

/**
 * MFA client interface available in both server and client contexts.
 */
export interface MfaClient {
  /**
   * List enrolled authenticators for the user.
   * Filters by allowed challenge types from mfa_requirements.
   *
   * @param options - Options containing encrypted mfaToken
   * @returns Array of authenticators
   */
  getAuthenticators(options: { mfaToken: string }): Promise<Authenticator[]>;

  /**
   * Initiate an MFA challenge.
   *
   * @param options - Challenge options
   * @returns Challenge response (oobCode, bindingMethod)
   */
  challenge(options: {
    mfaToken: string;
    challengeType: string;
    authenticatorId?: string;
  }): Promise<ChallengeResponse>;

  /**
   * Verify MFA code and complete authentication.
   * Stores the resulting tokens in the session cookie server-side.
   *
   * @param options - Verification options (otp | oobCode+bindingCode | recoveryCode)
   * @returns `{ success: true }` — call `getAccessToken()` afterward to retrieve the token.
   */
  verify(options: VerifyMfaOptions): Promise<MfaVerifyResponse>;

  /**
   * Enroll a new MFA authenticator during initial MFA setup.
   *
   * @param options - Enrollment options (otp | oob | email)
   * @returns Enrollment response with authenticator details and optional recovery codes
   */
  enroll(options: EnrollOptions): Promise<EnrollmentResponse>;
}

/**
 * MFA authenticator (enrolled factor).
 * Uses camelCase for SDK-facing interface.
 *
 * @example
 * ```typescript
 * const authenticators = await mfa.getAuthenticators({ mfaToken });
 *
 * const otpAuth = authenticators.find(a => a.authenticatorType === 'otp');
 * const smsAuth = authenticators.find(a => a.oobChannel === 'sms');
 * ```
 */
export interface Authenticator {
  /** Authenticator ID */
  id: string;
  /** Authenticator type (primary field mapped from authenticator_type) */
  authenticatorType: string;
  /** Direct type value (optional, feature-flagged field from Auth0 API) */
  type?: string;
  /** Whether authenticator is active */
  active: boolean;
  /** Authenticator name (user-defined or default) */
  name?: string;
  /** Phone number for OOB (masked) */
  phoneNumber?: string;
  /** OOB channel (sms, voice) */
  oobChannel?: string;
  /** ISO 8601 timestamp of creation */
  createdAt?: string;
  /** ISO 8601 timestamp of last authentication */
  lastAuthenticatedAt?: string;
}

/**
 * MFA challenge response.
 * Uses camelCase for SDK-facing interface.
 *
 * @example
 * ```typescript
 * const response = await mfa.challenge({
 *   mfaToken,
 *   challengeType: 'oob',
 *   authenticatorId: 'sms|dev_abc123'
 * });
 *
 * console.log(`Challenge type: ${response.challengeType}`);
 * console.log(`OOB code: ${response.oobCode}`);
 * console.log(`Binding method: ${response.bindingMethod}`); // 'prompt'
 * ```
 */
export interface ChallengeResponse {
  /** Challenge type (otp, oob) */
  challengeType: string;
  /** OOB code (for oob challenges) */
  oobCode?: string;
  /** Binding method (for oob challenges) */
  bindingMethod?: string;
}

/**
 * Base options for MFA verify.
 */
export interface VerifyMfaOptionsBase {
  /** Encrypted MFA token */
  mfaToken: string;
}

/**
 * Verification with OTP code from authenticator app.
 *
 * @example
 * ```typescript
 * import { mfa } from '@auth0/nextjs-auth0/client';
 *
 * try {
 *   await mfa.verify({
 *     mfaToken: encryptedToken,
 *     otp: '123456' // From Google Authenticator
 *   });
 *   // User authenticated, access token in session
 * } catch (error) {
 *   if (error instanceof MfaVerifyError) {
 *     console.error('Invalid OTP code');
 *   }
 * }
 * ```
 */
export interface VerifyMfaWithOtpOptions extends VerifyMfaOptionsBase {
  otp: string;
}

/**
 * Verification with OOB code sent via SMS/Email/Push.
 *
 * @example
 * ```typescript
 * // After calling challenge()
 * const challengeResponse = await mfa.challenge({
 *   mfaToken,
 *   challengeType: 'oob',
 *   authenticatorId: 'sms|dev_abc123'
 * });
 *
 * // User receives code "543210"
 * await mfa.verify({
 *   mfaToken,
 *   oobCode: challengeResponse.oobCode,
 *   bindingCode: '543210'
 * });
 * ```
 */
export interface VerifyMfaWithOobOptions extends VerifyMfaOptionsBase {
  oobCode: string;
  bindingCode: string;
}

/**
 * Verification with recovery code (backup).
 *
 * @example
 * ```typescript
 * // Using recovery code from enrollment
 * await mfa.verify({
 *   mfaToken,
 *   recoveryCode: 'ABCD-EFGH-IJKL-MNOP'
 * });
 * // Recovery code is single-use and invalidated after verification
 * ```
 */
export interface VerifyMfaWithRecoveryCodeOptions extends VerifyMfaOptionsBase {
  recoveryCode: string;
}

/**
 * MFA verification options (union type).
 */
export type VerifyMfaOptions =
  | VerifyMfaWithOtpOptions
  | VerifyMfaWithOobOptions
  | VerifyMfaWithRecoveryCodeOptions;

/**
 * MFA context embedded in encrypted token.
 * Self-contained with all information needed for challenge completion.
 */
export interface MfaContext {
  /** Raw mfa_token from Auth0 */
  mfaToken: string;
  /** API identifier that required MFA */
  audience: string;
  /** Scopes requested */
  scope: string;
  /** MFA requirements from Auth0 */
  mfaRequirements: MfaRequirements | undefined;
  /** Timestamp for TTL validation (milliseconds since epoch) */
  createdAt: number;
}
