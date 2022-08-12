import { HttpError } from 'http-errors';

type AuthErrorOptions = {
  code: string;
  message: string;
  name: string;
  cause?: Error;
  status?: number;
};

export abstract class AuthError extends Error {
  public readonly code: string;
  public readonly name: string;
  public readonly cause?: Error;
  public readonly status?: number;

  constructor(options: AuthErrorOptions) {
    super(appendCause(options.message, options.cause));
    this.code = options.code;
    this.name = options.name;
    this.cause = options.cause;
    this.status = options.status;
  }
}

export enum AccessTokenErrorCode {
  NO_SESSION = 'ERR_NO_SESSION',
  NO_ACCESS_TOKEN = 'ERR_NO_ACCESS_TOKEN',
  NO_REFRESH_TOKEN = 'ERR_NO_REFRESH_TOKEN',
  EXPIRED_ACCESS_TOKEN = 'ERR_EXPIRED_ACCESS_TOKEN',
  INSUFFICIENT_SCOPE = 'ERR_INSUFFICIENT_SCOPE'
}

/**
 * The error thrown by {@link GetAccessToken}
 *
 * @category Server
 */
export class AccessTokenError extends AuthError {
  /* istanbul ignore next */
  constructor(code: AccessTokenErrorCode, message: string) {
    super({ code: code, message: message, name: 'AccessTokenError' });

    // Capturing stack trace, excluding constructor call from it.
    Error.captureStackTrace(this, this.constructor);
    Object.setPrototypeOf(this, AccessTokenError.prototype);
  }
}

// eslint-disable-next-line max-len
// Basic escaping for putting untrusted data directly into the HTML body, per: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-1-html-encode-before-inserting-untrusted-data-into-html-element-content
export function htmlSafe(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function appendCause(errorMessage: string, cause?: Error): string {
  if (!cause) return errorMessage;
  const separator = errorMessage.endsWith('.') ? '' : '.';
  return `${errorMessage}${separator} CAUSE: ${htmlSafe(cause.message)}`;
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
export class HandlerError extends AuthError {
  public static readonly code: string = 'ERR_HANDLER_FAILURE';

  /* istanbul ignore next */
  constructor(error: Error | AuthError | HttpError) {
    let status: number | undefined;

    if ('status' in error) {
      status = error.status;
    }

    super({
      code: HandlerError.code,
      message: 'API route handler failed.',
      name: 'HandlerError',
      cause: error,
      status
    });
    Object.setPrototypeOf(this, HandlerError.prototype);
  }
}
