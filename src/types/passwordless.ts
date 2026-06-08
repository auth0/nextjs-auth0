/**
 * Grant type for passwordless OTP verification.
 * Used to exchange a one-time password for access/refresh tokens.
 *
 * @see https://auth0.com/docs/api/authentication#authenticate-user
 */
export const GRANT_TYPE_PASSWORDLESS_OTP =
  "http://auth0.com/oauth/grant-type/passwordless/otp";

/**
 * Options to start a passwordless flow via email.
 * Auth0 will send a magic link or OTP code to the provided email address.
 */
export interface PasswordlessStartEmailOptions {
  /** The passwordless connection to use. */
  connection: "email";
  /** The email address to send the code or link to. */
  email: string;
  /**
   * The type of credential to deliver.
   * - `'code'` — one-time password (OTP)
   * - `'link'` — magic link
   */
  send: "code" | "link";
  /**
   * BCP 47 language tag (e.g. `'en'`, `'fr'`, `'pt-BR'`) forwarded as
   * `x-request-language` to Auth0. Used to select the correct email
   * template language when multiple are configured on the connection.
   */
  language?: string;
  /**
   * Additional authentication parameters passed to Auth0 in the `authParams`
   * body field of `/passwordless/start`. Useful for magic-link flows where
   * you need to set `redirect_uri`, `scope`, or custom parameters.
   *
   * @example
   * ```ts
   * await auth0.passwordless.start({
   *   connection: 'email',
   *   email: 'user@example.com',
   *   send: 'link',
   *   authParams: { redirect_uri: 'https://example.com/callback', scope: 'openid profile' }
   * });
   * ```
   */
  authParams?: Record<string, string>;
}

/**
 * Options to start a passwordless flow via SMS.
 * Auth0 will send an OTP to the provided phone number.
 */
export interface PasswordlessStartSmsOptions {
  /** The passwordless connection to use. */
  connection: "sms";
  /** The phone number to send the OTP to, in E.164 format (e.g. `'+14155550100'`). */
  phoneNumber: string;
  /**
   * BCP 47 language tag (e.g. `'en'`, `'fr'`, `'pt-BR'`) forwarded as
   * `x-request-language` to Auth0. Used to select the correct SMS
   * template language when multiple are configured on the connection.
   */
  language?: string;
  /**
   * Additional authentication parameters passed to Auth0 in the `authParams`
   * body field of `/passwordless/start`.
   */
  authParams?: Record<string, string>;
}

/**
 * Options for starting a passwordless authentication flow.
 * Use the `connection` field to discriminate between email and SMS.
 */
export type PasswordlessStartOptions =
  | PasswordlessStartEmailOptions
  | PasswordlessStartSmsOptions;

/**
 * Options to verify an email passwordless OTP.
 */
export interface PasswordlessVerifyEmailOptions {
  /** The passwordless connection used when starting the flow. */
  connection: "email";
  /** The email address the code was sent to. */
  email: string;
  /** The verification code received by the user. */
  verificationCode: string;
}

/**
 * Options to verify an SMS passwordless OTP.
 */
export interface PasswordlessVerifySmsOptions {
  /** The passwordless connection used when starting the flow. */
  connection: "sms";
  /** The phone number the OTP was sent to. */
  phoneNumber: string;
  /** The verification code received by the user. */
  verificationCode: string;
}

/**
 * Options for verifying a passwordless OTP and completing login.
 * Use the `connection` field to discriminate between email and SMS.
 */
export type PasswordlessVerifyOptions =
  | PasswordlessVerifyEmailOptions
  | PasswordlessVerifySmsOptions;

/**
 * Token response returned by Auth0 after a successful passwordless OTP verification.
 * Uses snake_case to match Auth0 API and SPA SDK conventions.
 */
export interface PasswordlessVerifyTokenResponse {
  /** Access token */
  access_token: string;
  /** Refresh token (if offline_access scope was granted) */
  refresh_token?: string;
  /** ID token */
  id_token?: string;
  /** Token type (usually "Bearer") */
  token_type: string;
  /** Granted scope */
  scope?: string;
  /** Expires in seconds */
  expires_in: number;
}

/**
 * Public interface for the passwordless client.
 * Accessible via `auth0.passwordless` after initialization.
 */
export interface PasswordlessClient {
  /**
   * Starts a passwordless authentication flow by sending an OTP or magic link
   * to the user's email address or phone number.
   *
   * For magic link (`send: 'link'`) in App Router, the transaction cookie is
   * written via `next/headers` automatically. In Pages Router, pass explicit
   * `req` and `res` so the cookie can be set on the response.
   *
   * @param options - Connection type and user identifier.
   */
  start(options: PasswordlessStartOptions): Promise<void>;

  /**
   * Verifies the OTP entered by the user and establishes an authenticated session.
   *
   * @param options - Connection type, user identifier, and OTP code.
   */
  verify(options: PasswordlessVerifyOptions): Promise<void>;
}
