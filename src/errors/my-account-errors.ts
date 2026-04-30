import { SdkError } from "./sdk-error.js";

/**
 * Error class representing a connect account request error.
 */
export class MyAccountApiError extends SdkError {
  public name: string = "MyAccountApiError";
  public code: string = "my_account_api_error";
  public type: string;
  public title: string;
  public detail: string;
  public status: number;
  public validationErrors?: Array<{
    /**
     * A human-readable description of the specific error. Required.
     */
    detail: string;
    /**
     * The name of the invalid parameter. Optional.
     */
    field?: string;
    /**
     * A JSON Pointer that points to the exact location of the error in a JSON document being validated. Optional.
     */
    pointer?: string;
    /**
     *  Specifies the source of the error (e.g., body, query, or header in an HTML message). Optional.
     */
    source?: string;
  }>;

  constructor({
    type,
    title,
    detail,
    status,
    validationErrors
  }: {
    type: string;
    title: string;
    detail: string;
    status: number;
    validationErrors?: Array<{
      detail: string;
      field?: string;
      pointer?: string;
      source?: string;
    }>;
  }) {
    super(`${title}: ${detail}`);
    this.type = type;
    this.title = title;
    this.detail = detail;
    this.status = status;
    this.validationErrors = validationErrors;
  }
}

/**
 * Enum representing error codes related to the connect account flow.
 */
export enum ConnectAccountErrorCodes {
  /**
   * The session is missing.
   */
  MISSING_SESSION = "missing_session",

  /**
   * Failed to initiate the connect account flow.
   */
  FAILED_TO_INITIATE = "failed_to_initiate",

  /**
   * Failed to complete the connect account flow.
   */
  FAILED_TO_COMPLETE = "failed_to_complete"
}

/**
 * Error class representing a connect account error.
 */
export class ConnectAccountError extends SdkError {
  /**
   * The error code associated with the connect account error.
   */
  public code: string;
  public cause?: MyAccountApiError;

  constructor({
    code,
    message,
    cause
  }: {
    code: string;
    message: string;
    cause?: MyAccountApiError;
  }) {
    super(message);
    this.name = "ConnectAccountError";
    this.code = code;
    this.cause = cause;
  }
}
