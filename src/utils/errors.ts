import { HttpError } from 'http-errors';

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

/**
 * @ignore
 */
export function appendCause(errorMessage: string, cause?: Error): string {
  if (!cause) return errorMessage;
  const separator = errorMessage.endsWith('.') ? '' : '.';
  return `${errorMessage}${separator} CAUSE: ${htmlSafe(cause.message)}`;
}

type AuthErrorOptions = {
  code: string;
  message: string;
  name: string;
  cause?: Error;
  status?: number;
};

/**
 * The base class for all SDK errors.
 *
 * Because part of the error message can come from the OpenID Connect `error` query parameter we
 * do some basic escaping which makes sure the default error handler is safe from XSS.
 *
 * If you write your own error handler, you should **not** render the error message
 * without using a templating engine that will properly escape it for other HTML contexts first.
 *
 * Note that the error message of the {@link AuthError.cause | underlying error} is **not** escaped
 * in any way, so do **not** render it without escaping it first!
 *
 * @category Server
 */
export abstract class AuthError extends Error {
  /**
   * A machine-readable error code that remains stable within a major version of the SDK. You
   * should rely on this error code to handle errors. In contrast, the error message is not part of
   * the API and can change anytime. Do **not** parse or otherwise rely on the error message to
   * handle errors.
   */
  public readonly code: string;

  /**
   * The error class name.
   */
  public readonly name: string;

  /**
   * The underlying error, if any. The error message of this underlying error is **not** escaped in
   * any way, so do **not** render it without escaping it first!
   */
  public readonly cause?: Error;

  /**
   * The HTTP status code, if any.
   */
  public readonly status?: number;

  /* istanbul ignore next */
  constructor(options: AuthErrorOptions) {
    super(appendCause(options.message, options.cause));
    this.code = options.code;
    this.name = options.name;
    this.cause = options.cause;
    this.status = options.status;
  }
}

/**
 * Error codes for {@link AccessTokenError}.
 *
 * @category Server
 */
export enum AccessTokenErrorCode {
  MISSING_SESSION = 'ERR_MISSING_SESSION',
  MISSING_ACCESS_TOKEN = 'ERR_MISSING_ACCESS_TOKEN',
  MISSING_REFRESH_TOKEN = 'ERR_MISSING_REFRESH_TOKEN',
  EXPIRED_ACCESS_TOKEN = 'ERR_EXPIRED_ACCESS_TOKEN',
  INSUFFICIENT_SCOPE = 'ERR_INSUFFICIENT_SCOPE'
}

/**
 * The error thrown by {@link GetAccessToken}.
 *
 * @see the {@link AuthError.code | code property} contains a machine-readable error code that
 * remains stable within a major version of the SDK. You should rely on this error code to handle
 * errors. In contrast, the error message is not part of the API and can change anytime. Do **not**
 * parse or otherwise rely on the error message to handle errors.
 *
 * @see {@link AccessTokenErrorCode} for the list of all possible error codes.
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

/**
 * @ignore
 */
export type HandlerErrorCause = Error | AuthError | HttpError;

type HandlerErrorOptions = {
  code: string;
  message: string;
  name: string;
  cause: HandlerErrorCause;
};

/**
 * The base class for errors thrown by API route handlers. It extends {@link AuthError}.
 *
 * Because part of the error message can come from the OpenID Connect `error` query parameter we
 * do some basic escaping which makes sure the default error handler is safe from XSS.
 *
 * If you write your own error handler, you should **not** render the error message
 * without using a templating engine that will properly escape it for other HTML contexts first.
 *
 * @see the {@link AuthError.cause | cause property} contains the underlying error.
 * The error message of this underlying error is **not** escaped in any way, so do **not** render
 * it without escaping it first!
 *
 * @see the {@link AuthError.status | status property} contains the HTTP status code of the error,
 * if any.
 *
 * @category Server
 */
export class HandlerError extends AuthError {
  /* istanbul ignore next */
  constructor(options: HandlerErrorOptions) {
    let status: number | undefined;
    if ('status' in options.cause) status = options.cause.status;
    super({ ...options, status });
  }
}

/**
 * The error thrown by the callback API route handler. It extends {@link HandlerError}.
 *
 * Because part of the error message can come from the OpenID Connect `error` query parameter we
 * do some basic escaping which makes sure the default error handler is safe from XSS.
 *
 * If you write your own error handler, you should **not** render the error message
 * without using a templating engine that will properly escape it for other HTML contexts first.
 *
 * @see the {@link AuthError.cause | cause property} contains the underlying error.
 * The error message of this underlying error is **not** escaped in any way, so do **not** render
 * it without escaping it first!
 *
 * @see the {@link AuthError.status | status property} contains the HTTP status code of the error,
 * if any.
 *
 * @category Server
 */
export class CallbackHandlerError extends HandlerError {
  public static readonly code: string = 'ERR_CALLBACK_HANDLER_FAILURE';

  /* istanbul ignore next */
  constructor(cause: HandlerErrorCause) {
    super({
      code: CallbackHandlerError.code,
      message: 'Callback handler failed.',
      name: 'CallbackHandlerError',
      cause
    });
    Object.setPrototypeOf(this, CallbackHandlerError.prototype);
  }
}

/**
 * The error thrown by the login API route handler. It extends {@link HandlerError}.
 *
 * @see the {@link AuthError.cause | cause property} contains the underlying error.
 * @category Server
 */
export class LoginHandlerError extends HandlerError {
  public static readonly code: string = 'ERR_LOGIN_HANDLER_FAILURE';

  /* istanbul ignore next */
  constructor(cause: HandlerErrorCause) {
    super({
      code: LoginHandlerError.code,
      message: 'Login handler failed.',
      name: 'LoginHandlerError',
      cause
    });
    Object.setPrototypeOf(this, LoginHandlerError.prototype);
  }
}

/**
 * The error thrown by the logout API route handler. It extends {@link HandlerError}.
 *
 * @see the {@link AuthError.cause | cause property} contains the underlying error.
 * @category Server
 */
export class LogoutHandlerError extends HandlerError {
  public static readonly code: string = 'ERR_LOGOUT_HANDLER_FAILURE';

  /* istanbul ignore next */
  constructor(cause: HandlerErrorCause) {
    super({
      code: LogoutHandlerError.code,
      message: 'Logout handler failed.',
      name: 'LogoutHandlerError',
      cause
    });
    Object.setPrototypeOf(this, LogoutHandlerError.prototype);
  }
}

/**
 * The error thrown by the profile API route handler. It extends {@link HandlerError}.
 *
 * @see the {@link AuthError.cause | cause property} contains the underlying error.
 * @category Server
 */
export class ProfileHandlerError extends HandlerError {
  public static readonly code: string = 'ERR_PROFILE_HANDLER_FAILURE';

  /* istanbul ignore next */
  constructor(cause: HandlerErrorCause) {
    super({
      code: ProfileHandlerError.code,
      message: 'Profile handler failed.',
      name: 'ProfileHandlerError',
      cause
    });
    Object.setPrototypeOf(this, ProfileHandlerError.prototype);
  }
}
