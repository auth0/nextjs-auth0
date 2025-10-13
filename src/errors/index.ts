export abstract class SdkError extends Error {
  public abstract code: string;
}

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

export class BackchannelLogoutError extends SdkError {
  public code: string = "backchannel_logout_error";

  constructor(message?: string) {
    super(
      message ??
        "An error occurred while completing the backchannel logout request."
    );
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
 * Error class representing a connect account request error.
 */
export class MyAccountApiError extends SdkError {
  public name: string = "MyAccountApiError";
  public code: string = "my_account_api_error";
  public type: string;
  public title: string;
  public detail: string;
  public status: number;
  public validationErrors?: Array<{
    /**
     * A human-readable description of the specific error. Required.
     */
    detail: string;
    /**
     * The name of the invalid parameter. Optional.
     */
    field?: string;
    /**
     * A JSON Pointer that points to the exact location of the error in a JSON document being validated. Optional.
     */
    pointer?: string;
    /**
     *  Specifies the source of the error (e.g., body, query, or header in an HTML message). Optional.
     */
    source?: string;
  }>;

  constructor({
    type,
    title,
    detail,
    status,
    validationErrors
  }: {
    type: string;
    title: string;
    detail: string;
    status: number;
    validationErrors?: Array<{
      detail: string;
      field?: string;
      pointer?: string;
      source?: string;
    }>;
  }) {
    super(`${title}: ${detail}`);
    this.type = type;
    this.title = title;
    this.detail = detail;
    this.status = status;
    this.validationErrors = validationErrors;
  }
}

/**
 * Enum representing error codes related to the connect account flow.
 */
export enum ConnectAccountErrorCodes {
  /**
   * The session is missing.
   */
  MISSING_SESSION = "missing_session",

  /**
   * Failed to initiate the connect account flow.
   */
  FAILED_TO_INITIATE = "failed_to_initiate",

  /**
   * Failed to complete the connect account flow.
   */
  FAILED_TO_COMPLETE = "failed_to_complete"
}

/**
 * Error class representing a connect account error.
 */
export class ConnectAccountError extends SdkError {
  /**
   * The error code associated with the connect account error.
   */
  public code: string;
  public cause?: MyAccountApiError;

  constructor({
    code,
    message,
    cause
  }: {
    code: string;
    message: string;
    cause?: MyAccountApiError;
  }) {
    super(message);
    this.name = "ConnectAccountError";
    this.code = code;
    this.cause = cause;
  }
}
