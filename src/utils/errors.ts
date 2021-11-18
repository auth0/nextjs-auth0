import { HttpError } from 'http-errors';

/**
 * The error thrown by {@link GetAccessToken}
 *
 * @category Server
 */
export class AccessTokenError extends Error {
  public code: string;

  /* istanbul ignore next */
  constructor(code: string, message: string) {
    super(message);

    // Saving class name in the property of our custom error as a shortcut.
    this.name = this.constructor.name;

    // Capturing stack trace, excluding constructor call from it.
    Error.captureStackTrace(this, this.constructor);

    // Machine readable code.
    this.code = code;
    Object.setPrototypeOf(this, AccessTokenError.prototype);
  }
}

// eslint-disable-next-line max-len
// Basic escaping for putting untrusted data directly into the HTML body, per: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-1-html-encode-before-inserting-untrusted-data-into-html-element-content
function htmlSafe(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * The error thrown by API route handlers.
 *
 * Because the error message can come from the OpenID Connect `error` query parameter we
 * do some basic escaping which makes sure the default error handler is safe from XSS.
 *
 * If you write your own error handler, you should **not** render the error message
 * without using a templating engine that will properly escape it for other HTML contexts first.
 *
 * @category Server
 */
export class HandlerError extends Error {
  public status: number | undefined;
  public code: string | undefined;

  /* istanbul ignore next */
  constructor(error: Error | AccessTokenError | HttpError) {
    super(htmlSafe(error.message));

    this.name = error.name;

    if ('code' in error) {
      this.code = error.code;
    }

    if ('status' in error) {
      this.status = error.status;
    }
    Object.setPrototypeOf(this, HandlerError.prototype);
  }
}
