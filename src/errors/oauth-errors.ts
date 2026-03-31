import { SdkError } from "./sdk-error.js";

/**
 * Errors that come from Auth0 in the `redirect_uri` callback may contain reflected user input via the OpenID Connect `error` and `error_description` query parameter.
 * You should **not** render the error `message`, or `error` and `error_description` properties without properly escaping them first.
 */
export class OAuth2Error extends SdkError {
  public code: string;

  constructor({ code, message }: { code: string; message?: string }) {
    super(
      message ??
        "An error occurred while interacting with the authorization server."
    );
    this.name = "OAuth2Error";
    this.code = code;
  }
}

export class DiscoveryError extends SdkError {
  public code: string = "discovery_error";

  constructor(message?: string) {
    super(message ?? "Discovery failed for the OpenID Connect configuration.");
    this.name = "DiscoveryError";
  }
}

export class MissingStateError extends SdkError {
  public code: string = "missing_state";

  constructor(message?: string) {
    super(message ?? "The state parameter is missing.");
    this.name = "MissingStateError";
  }
}

export class InvalidStateError extends SdkError {
  public code: string = "invalid_state";

  constructor(message?: string) {
    super(message ?? "The state parameter is invalid.");
    this.name = "InvalidStateError";
  }
}

export class InvalidConfigurationError extends SdkError {
  public code: string = "invalid_configuration";

  constructor(message?: string) {
    super(message ?? "The configuration is invalid.");
    this.name = "InvalidConfigurationError";
  }
}

export class AuthorizationError extends SdkError {
  public code: string = "authorization_error";
  public cause: OAuth2Error;

  constructor({ cause, message }: { cause: OAuth2Error; message?: string }) {
    super(message ?? "An error occurred during the authorization flow.");
    this.cause = cause;
    this.name = "AuthorizationError";
  }
}

export class AuthorizationCodeGrantRequestError extends SdkError {
  public code: string = "authorization_code_grant_request_error";

  constructor(message?: string) {
    super(
      message ??
        "An error occurred while preparing or performing the authorization code grant request."
    );
    this.name = "AuthorizationCodeGrantRequestError";
  }
}

export class AuthorizationCodeGrantError extends SdkError {
  public code: string = "authorization_code_grant_error";
  public cause: OAuth2Error;

  constructor({ cause, message }: { cause: OAuth2Error; message?: string }) {
    super(
      message ??
        "An error occurred while trying to exchange the authorization code."
    );
    this.cause = cause;
    this.name = "AuthorizationCodeGrantError";
  }
}

/**
 * Error thrown when backchannel logout processing fails.
 *
 * Error codes:
 * - `backchannel_logout_error` - Generic/default error
 * - `untrusted_issuer` - Token issuer not in configured trustedDomains
 * - `missing_trust_config` - trustedDomains not provided in resolver mode
 * - `missing_iss_claim` - Token missing required `iss` claim
 * - `malformed_token` - Token decode or validation failed
 */
export class BackchannelLogoutError extends SdkError {
  public code: string;

  /**
   * Creates a new BackchannelLogoutError.
   *
   * Overloaded constructor signatures:
   * 1. `new BackchannelLogoutError(message)` — backward compatible, uses default code
   * 2. `new BackchannelLogoutError(code, message)` — new parameterized form
   *
   * The constructor distinguishes between forms by checking if both parameters are
   * provided AND the first parameter is a non-empty string (indicating a code value).
   *
   * @param codeOrMessage - Either error code string or error message (for backward compat)
   * @param messageOrUndefined - Error message (only when codeOrMessage is code)
   */
  constructor(codeOrMessage?: string, messageOrUndefined?: string) {
    // Backward compatibility: only treat as new form if BOTH args are strings and first is non-empty
    let code: string;
    let message: string;

    if (
      typeof codeOrMessage === "string" &&
      typeof messageOrUndefined === "string" &&
      codeOrMessage.length > 0
    ) {
      // New form: BackchannelLogoutError(code, message)
      code = codeOrMessage;
      message = messageOrUndefined;
    } else {
      // Old form: BackchannelLogoutError(message)
      code = "backchannel_logout_error";
      message =
        codeOrMessage ??
        "An error occurred while completing the backchannel logout request.";
    }

    super(message);
    this.code = code;
    this.name = "BackchannelLogoutError";
  }
}

export class BackchannelAuthenticationNotSupportedError extends SdkError {
  public code: string = "backchannel_authentication_not_supported_error";

  constructor() {
    super(
      "The authorization server does not support backchannel authentication. Learn how to enable it here: https://auth0.com/docs/get-started/applications/configure-client-initiated-backchannel-authentication"
    );
    this.name = "BackchannelAuthenticationNotSupportedError";
  }
}

export class BackchannelAuthenticationError extends SdkError {
  public code: string = "backchannel_authentication_error";
  public cause?: OAuth2Error;

  constructor({ cause }: { cause?: OAuth2Error }) {
    super(
      "There was an error when trying to use Client-Initiated Backchannel Authentication."
    );
    this.cause = cause;
    this.name = "BackchannelAuthenticationError";
  }
}

export enum AccessTokenErrorCode {
  MISSING_SESSION = "missing_session",
  MISSING_REFRESH_TOKEN = "missing_refresh_token",
  FAILED_TO_REFRESH_TOKEN = "failed_to_refresh_token"
}

export class AccessTokenError extends SdkError {
  public code: string;
  public cause?: OAuth2Error;

  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);
    this.name = "AccessTokenError";
    this.code = code;
    this.cause = cause;
  }
}

/**
 * Enum representing error codes related to access tokens for connections.
 */
export enum AccessTokenForConnectionErrorCode {
  /**
   * The session is missing.
   */
  MISSING_SESSION = "missing_session",

  /**
   * The refresh token is missing.
   */
  MISSING_REFRESH_TOKEN = "missing_refresh_token",

  /**
   * Failed to exchange the refresh token.
   */
  FAILED_TO_EXCHANGE = "failed_to_exchange_refresh_token"
}

/**
 * Error class representing an access token for connection error.
 * Extends the `SdkError` class.
 */
export class AccessTokenForConnectionError extends SdkError {
  /**
   * The error code associated with the access token error.
   */
  public code: string;
  public cause?: OAuth2Error;

  /**
   * Constructs a new `AccessTokenForConnectionError` instance.
   *
   * @param code - The error code.
   * @param message - The error message.
   * @param cause - The OAuth2 cause of the error.
   */
  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);
    this.name = "AccessTokenForConnectionError";
    this.code = code;
    this.cause = cause;
  }
}

/**
 * Error codes for Custom Token Exchange errors.
 */
export enum CustomTokenExchangeErrorCode {
  /**
   * The subject_token is missing or empty.
   */
  MISSING_SUBJECT_TOKEN = "missing_subject_token",

  /**
   * The subject_token_type is not a valid URI, wrong length, or uses a reserved namespace.
   */
  INVALID_SUBJECT_TOKEN_TYPE = "invalid_subject_token_type",

  /**
   * The actor_token was provided without actor_token_type.
   */
  MISSING_ACTOR_TOKEN_TYPE = "missing_actor_token_type",

  /**
   * The token exchange request failed.
   */
  EXCHANGE_FAILED = "exchange_failed"
}

/**
 * Error class representing a Custom Token Exchange error.
 * Extends the `SdkError` class.
 *
 * This error is thrown when a Custom Token Exchange operation fails,
 * such as validation errors or server-side token exchange failures.
 *
 * @see {@link https://auth0.com/docs/authenticate/custom-token-exchange Auth0 Custom Token Exchange Documentation}
 */
export class CustomTokenExchangeError extends SdkError {
  /**
   * The error code associated with the custom token exchange error.
   */
  public code: string;
  /**
   * The underlying OAuth2 error that caused this error (if applicable).
   */
  public cause?: OAuth2Error;

  /**
   * Constructs a new `CustomTokenExchangeError` instance.
   *
   * @param code - The error code.
   * @param message - The error message.
   * @param cause - The OAuth2 cause of the error.
   */
  constructor(code: string, message: string, cause?: OAuth2Error) {
    super(message);
    this.name = "CustomTokenExchangeError";
    this.code = code;
    this.cause = cause;
  }
}
