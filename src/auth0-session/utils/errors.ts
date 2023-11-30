export class EscapedError extends Error {
  /**
   * **WARNING** The message can contain user input and is only escaped using basic escaping for putting untrusted data
   * directly into the HTML body
   */
  constructor(message: string) {
    /* c8 ignore next */
    super(htmlSafe(message));
    Object.setPrototypeOf(this, EscapedError.prototype);
  }
}

export class MissingStateParamError extends Error {
  static message = 'Missing state parameter in Authorization Response.';
  status = 400;
  statusCode = 400;

  constructor() {
    /* c8 ignore next */
    super(MissingStateParamError.message);
    Object.setPrototypeOf(this, MissingStateParamError.prototype);
  }
}

export class MalformedStateCookieError extends Error {
  static message = 'Your state cookie is not valid JSON.';
  status = 400;
  statusCode = 400;

  constructor() {
    /* c8 ignore next */
    super(MalformedStateCookieError.message);
    Object.setPrototypeOf(this, MalformedStateCookieError.prototype);
  }
}

export class MissingStateCookieError extends Error {
  static message = 'Missing state cookie from login request (check login URL, callback URL and cookie config).';
  status = 400;
  statusCode = 400;

  constructor() {
    /* c8 ignore next */
    super(MissingStateCookieError.message);
    Object.setPrototypeOf(this, MissingStateCookieError.prototype);
  }
}

export class ApplicationError extends EscapedError {
  /**
   * **WARNING** The message can contain user input and is only escaped using basic escaping for putting untrusted data
   * directly into the HTML body
   */
  constructor(rpError: Error) {
    /* c8 ignore next */
    super(rpError.message);
    Object.setPrototypeOf(this, ApplicationError.prototype);
  }
}

export class IdentityProviderError extends EscapedError {
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
   * **WARNING** The message can contain user input and is only escaped using basic escaping for putting untrusted data
   * directly into the HTML body
   */
  constructor(rpError: { message: string; error?: string; error_description?: string }) {
    /* c8 ignore next */
    super(rpError.message);
    this.error = htmlSafe(rpError.error);
    this.errorDescription = htmlSafe(rpError.error_description);
    Object.setPrototypeOf(this, IdentityProviderError.prototype);
  }
}

export class DiscoveryError extends EscapedError {
  constructor(error: Error | (Error & { _errors: Error[] }), issuerBaseUrl: string) {
    /* c8 ignore next */
    super(`Discovery requests failing for ${issuerBaseUrl}, ${error.message}`);
    Object.setPrototypeOf(this, DiscoveryError.prototype);
  }
}

export class UserInfoError extends EscapedError {
  constructor(msg: string) {
    /* c8 ignore next */
    super(`Userinfo request failing with: ${msg}`);
    Object.setPrototypeOf(this, UserInfoError.prototype);
  }
}

export class BackchannelLogoutError extends Error {
  constructor(public code: string, public description: string) {
    /* c8 ignore next */
    super(description);
    Object.setPrototypeOf(this, BackchannelLogoutError.prototype);
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
