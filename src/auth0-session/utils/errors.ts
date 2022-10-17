import type { errors } from 'openid-client';

export class MissingStateParamError extends Error {
  static message =
    'This endpoint must be called as part of the login flow (with a state parameter from the initial' +
    ' authorization request).';

  constructor() {
    /* c8 ignore next */
    super(MissingStateParamError.message);
    Object.setPrototypeOf(this, MissingStateParamError.prototype);
  }
}

export class MissingStateCookieError extends Error {
  static message =
    'The cookie dropped by the login request cannot be found, check the url of the login request, the url of' +
    ' this callback request and your cookie config.';

  constructor() {
    /* c8 ignore next */
    super(MissingStateCookieError.message);
    Object.setPrototypeOf(this, MissingStateCookieError.prototype);
  }
}

export class ApplicationError extends Error {
  constructor(rpError: errors.RPError) {
    /* c8 ignore next */
    super(rpError.message);
    Object.setPrototypeOf(this, ApplicationError.prototype);
  }
}

export class IdentityProviderError extends Error {
  /**
   * The 'error_description' parameter from the AS response.
   * **WARNING** This can contain user input and is only escaped using basic escaping for putting untrusted data
   * directly into the HTML body
   */
  errorDescription?: string;
  /**
   * The 'error' parameter from the AS response
   * **WARNING** This can contain user input and is only escaped using basic escaping for putting untrusted data
   * directly into the HTML body
   */
  error?: string;

  /**
   * **WARNING** The message contain user input and is only escaped using basic escaping for putting untrusted data
   * directly into the HTML body
   */
  constructor(rpError: errors.OPError) {
    /* c8 ignore next */
    super(htmlSafe(rpError.message));
    this.error = htmlSafe(rpError.error);
    this.errorDescription = htmlSafe(rpError.error_description);
    Object.setPrototypeOf(this, IdentityProviderError.prototype);
  }
}

// eslint-disable-next-line max-len
// Basic escaping for putting untrusted data directly into the HTML body, per: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-1-html-encode-before-inserting-untrusted-data-into-html-element-content.
export function htmlSafe(input?: string): string | undefined {
  return (
    input &&
    input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
  );
}
