/**
 * The error thrown by {@link GetAccessToken}
 *
 * @category Server
 */
export class AccessTokenError extends Error {
  public code: string;

  constructor(code: string, message: string) {
    super(message);

    // Saving class name in the property of our custom error as a shortcut.
    this.name = this.constructor.name;

    // Capturing stack trace, excluding constructor call from it.
    Error.captureStackTrace(this, this.constructor);

    // Machine readable code.
    this.code = code;
  }
}
