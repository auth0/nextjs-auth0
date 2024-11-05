export abstract class SdkError extends Error {
  public abstract code: string
}

export class OAuth2Error extends SdkError {
  public code: string

  constructor({ code, message }: { code: string; message?: string }) {
    // TODO: sanitize error message or add warning
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

export class MissingRefreshToken extends SdkError {
  public code: string = "missing_refresh_token"

  constructor(message?: string) {
    super(
      message ??
        "The access token has expired and a refresh token was not granted."
    )
    this.name = "MissingRefreshToken"
  }
}

export class RefreshTokenGrantError extends SdkError {
  public code: string = "refresh_token_grant_error"
  public cause: OAuth2Error

  constructor({ cause, message }: { cause: OAuth2Error; message?: string }) {
    super(
      message ?? "An error occured while trying to refresh the access token."
    )
    this.cause = cause
    this.name = "RefreshTokenGrantError"
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
