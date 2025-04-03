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
        "An error occured while interacting with the authorization server."
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

export class AuthorizationError extends SdkError {
  public code: string = "authorization_error";
  public cause: OAuth2Error;

  constructor({ cause, message }: { cause: OAuth2Error; message?: string }) {
    super(message ?? "An error occured during the authorization flow.");
    this.cause = cause;
    this.name = "AuthorizationError";
  }
}

export class AuthorizationCodeGrantError extends SdkError {
  public code: string = "authorization_code_grant_error";
  public cause: OAuth2Error;

  constructor({ cause, message }: { cause: OAuth2Error; message?: string }) {
    super(
      message ??
        "An error occured while trying to exchange the authorization code."
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
        "An error occured while completing the backchannel logout request."
    );
    this.name = "BackchannelLogoutError";
  }
}

export enum AccessTokenErrorCode {
  MISSING_SESSION = "missing_session",
  MISSING_REFRESH_TOKEN = "missing_refresh_token",
  FAILED_TO_REFRESH_TOKEN = "failed_to_refresh_token"
}

export class AccessTokenError extends SdkError {
  public code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "AccessTokenError";
    this.code = code;
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
 * Enum representing error codes related to configuration.
 */
export enum ConfigurationErrorCode {
  /**
   * Missing required configuration options.
   */
  MISSING_REQUIRED_OPTIONS = "missing_required_options"
}

/**
 * Error class representing a configuration error.
 * Extends the `SdkError` class.
 */
export class ConfigurationError extends SdkError {
  /**
   * The error code associated with the configuration error.
   */
  public code: string;
  public missingOptions?: string[];

  /**
   * Constructs a new `ConfigurationError` instance.
   *
   * @param code - The error code.
   * @param missingOptions - Array of missing configuration option names.
   * @param envVarMapping - Optional mapping of option names to their environment variable names.
   */
  constructor(
    code: string,
    missingOptions: string[] = [],
    envVarMapping: Record<string, string> = {}
  ) {
    // Standard intro message explaining the issue
    let errorMessage =
      "Not all required options where provided when creating an instance of Auth0Client. Ensure to provide all missing options, either by passing it to the Auth0Client constructor, or by setting the corresponding environment variable.\n\n";

    // Add specific details for each missing option
    missingOptions.forEach((key) => {
      if (key === "clientAuthentication") {
        errorMessage += `Missing: clientAuthentication: Set either AUTH0_CLIENT_SECRET env var or AUTH0_CLIENT_ASSERTION_SIGNING_KEY env var, or pass clientSecret or clientAssertionSigningKey in options\n`;
      } else if (envVarMapping[key]) {
        errorMessage += `Missing: ${key}: Set ${envVarMapping[key]} env var or pass ${key} in options\n`;
      } else {
        errorMessage += `Missing: ${key}\n`;
      }
    });

    super(errorMessage.trim());
    this.name = "ConfigurationError";
    this.code = code;
    this.missingOptions = missingOptions;
  }
}
