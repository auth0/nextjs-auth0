import { SdkError } from "./index.js";

/**
 * Thrown when request validation fails (missing/invalid params).
 * Mapped to 400 Bad Request.
 */
export class InvalidRequestError extends SdkError {
  public code = "invalid_request";

  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, InvalidRequestError.prototype);
    this.name = "InvalidRequestError";
  }

  toJSON() {
    return {
      error: this.code,
      error_description: this.message
    };
  }
}
