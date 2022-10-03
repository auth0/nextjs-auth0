import type { errors } from 'openid-client';

export class MissingStateParamError extends Error {
  static message =
    'This endpoint must be called as part of the login flow (with a state parameter from the initial authorization request).';

  constructor() {
    /* c8 ignore next */
    super(MissingStateParamError.message);
  }
}

export class MissingStateCookieError extends Error {
  static message =
    'The cookie dropped by the login request cannot be found, check the url of the login request, the url of this callback request and your cookie config.';

  constructor() {
    /* c8 ignore next */
    super(MissingStateCookieError.message);
  }
}

export class ApplicationError extends Error {
  constructor(rpError: errors.RPError) {
    /* c8 ignore next */
    super(rpError.message);
  }
}

export class IdentityProviderError extends Error {
  /**
   * The 'error_description' parameter from the AS response (Warning: this can contain user input and is not escaped in any way).
   */
  errorDescription?: string;
  /**
   * The 'error' parameter from the AS response  (Warning: this can contain user input and is not escaped in any way).
   */
  error?: string;

  /**
   * Warning: the message can contain user input and is not escaped in any way.
   */
  constructor(rpError: errors.OPError) {
    /* c8 ignore next */
    super(rpError.message);
    this.error = rpError.error;
    this.errorDescription = rpError.error_description;
  }
}
