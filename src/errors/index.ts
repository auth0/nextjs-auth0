export abstract class SdkError extends Error {
  public abstract code: string
}

/**
 * Errors that come from Auth0 in the `redirect_uri` callback may contain reflected user input via the OpenID Connect `error` and `error_description` query parameter.
 * You should **not** render the error `message`, or `error` and `error_description` properties without properly escaping them first.
 */
export class OAuth2Error extends SdkError {
  public code: string

  constructor({ code, message }: { code: string; message?: string }) {
    super(
      message ??
        "An error occured while interacting with the authorization server."
    )
    this.name = "OAuth2Error"
    this.code = code
  }
}

export class DiscoveryError extends SdkError {
  public code: string = "discovery_error"

  constructor(message?: string) {
    super(message ?? "Discovery failed for the OpenID Connect configuration.")
    this.name = "DiscoveryError"
  }
}

export class MissingStateError extends SdkError {
  public code: string = "missing_state"

  constructor(message?: string) {
    super(message ?? "The state parameter is missing.")
    this.name = "MissingStateError"
  }
}

export class InvalidStateError extends SdkError {
  public code: string = "invalid_state"

  constructor(message?: string) {
    super(message ?? "The state parameter is invalid.")
    this.name = "InvalidStateError"
  }
}

export class AuthorizationError extends SdkError {
  public code: string = "authorization_error"
  public cause: OAuth2Error

  constructor({ cause, message }: { cause: OAuth2Error; message?: string }) {
    super(message ?? "An error occured during the authorization flow.")
    this.cause = cause
    this.name = "AuthorizationError"
  }
}

export class AuthorizationCodeGrantError extends SdkError {
  public code: string = "authorization_code_grant_error"
  public cause: OAuth2Error

  constructor({ cause, message }: { cause: OAuth2Error; message?: string }) {
    super(
      message ??
        "An error occured while trying to exchange the authorization code."
    )
    this.cause = cause
    this.name = "AuthorizationCodeGrantError"
  }
}

export class BackchannelLogoutError extends SdkError {
  public code: string = "backchannel_logout_error"

  constructor(message?: string) {
    super(
      message ??
        "An error occured while completing the backchannel logout request."
    )
    this.name = "BackchannelLogoutError"
  }
}

export enum AccessTokenErrorCode {
  MISSING_SESSION = "missing_session",
  MISSING_REFRESH_TOKEN = "missing_refresh_token",
  FAILED_TO_REFRESH_TOKEN = "failed_to_refresh_token",
}

export class AccessTokenError extends SdkError {
  public code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = "AccessTokenError"
    this.code = code
  }
}

export enum FederatedConnectionAccessTokenErrorCode {
  MISSING_SESSION = "missing_session",
  MISSING_REFRESH_TOKEN = "missing_refresh_token",

  FAILED_TO_EXCHANGE = "failed_to_exchange_refresh_token",
}

export class FederatedConnectionsAccessTokenError extends SdkError {
  public code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = "FederatedConnectionAccessTokenError"
    this.code = code
  }
}
