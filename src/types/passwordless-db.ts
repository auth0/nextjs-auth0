/**
 * Delivery method for phone OTP.
 */
export type PasswordlessDbDeliveryMethod = "text" | "voice";

/**
 * Options to request a passwordless OTP challenge for a database connection user
 * identified by email address.
 *
 * The challenge always returns successfully regardless of whether the user exists
 * (user-enumeration prevention). If the user does not exist and `allowSignup` is
 * `false`, or if the user is blocked, the returned `auth_session` will be
 * non-functional and `loginWithOtp` will fail with `invalid_request`.
 *
 * A successful challenge does not guarantee an OTP was delivered.
 */
export interface PasswordlessDbChallengeEmailOptions {
  /** The email address to send the OTP to. */
  email: string;
  /** The database connection name configured with `email_otp`. */
  connection: string;
  /**
   * Whether to allow signup for users who do not yet exist in the connection.
   * Defaults to `false`. When `false`, non-existent users receive a silent
   * fake `auth_session` (no OTP sent) for GDPR compliance.
   */
  allowSignup?: boolean;
}

/**
 * Options to request a passwordless OTP challenge for a database connection user
 * identified by phone number.
 *
 * Same 200-always contract as {@link PasswordlessDbChallengeEmailOptions}.
 */
export interface PasswordlessDbChallengePhoneOptions {
  /** The phone number to send the OTP to, in E.164 format (e.g. `'+14155550100'`). */
  phoneNumber: string;
  /** The database connection name configured with `phone_otp`. */
  connection: string;
  /**
   * OTP delivery channel.
   * - `'text'` — SMS (default)
   * - `'voice'` — voice call
   */
  deliveryMethod?: PasswordlessDbDeliveryMethod;
  /**
   * Whether to allow signup for users who do not yet exist in the connection.
   * Defaults to `false`.
   */
  allowSignup?: boolean;
}

/**
 * The opaque challenge token returned by `POST /otp/challenge`.
 *
 * Treat `authSession` as a black box — never parse, log, or persist it beyond
 * the in-flight OTP verification flow.
 */
export interface PasswordlessDbChallenge {
  /** Opaque session handle returned by Auth0. Pass directly to `loginWithOtp`. */
  authSession: string;
}

/**
 * Options to exchange a challenge `auth_session` and user-entered OTP for tokens.
 *
 * Throws `PasswordlessDbGetTokenError` with `error: "invalid_request"` if the
 * `auth_session` was non-functional (blocked user, signup disabled for a
 * non-existent user, wrong OTP, or expired session).
 */
export interface PasswordlessDbGetTokenOptions {
  /** The opaque `authSession` returned by `challengeWithEmail` or `challengeWithPhoneNumber`. */
  authSession: string;
  /** The one-time password entered by the user. */
  otp: string;
}
