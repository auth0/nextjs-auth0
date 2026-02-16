import { SdkError } from "./sdk-error.js";

export class PopupBlockedError extends SdkError {
  public code = "popup_blocked" as const;

  constructor(message?: string) {
    super(
      message || "Popup was blocked by browser. Enable popups for this site."
    );
    this.name = "PopupBlockedError";
    Object.setPrototypeOf(this, PopupBlockedError.prototype);
  }
}

export class PopupCancelledError extends SdkError {
  public code = "popup_cancelled" as const;

  constructor(message?: string) {
    super(message || "Popup was closed by user");
    this.name = "PopupCancelledError";
    Object.setPrototypeOf(this, PopupCancelledError.prototype);
  }
}

export class PopupTimeoutError extends SdkError {
  public code = "popup_timeout" as const;

  constructor(message?: string) {
    super(message || "Popup did not complete within timeout");
    this.name = "PopupTimeoutError";
    Object.setPrototypeOf(this, PopupTimeoutError.prototype);
  }
}

export class PopupInProgressError extends SdkError {
  public code = "popup_in_progress" as const;

  constructor(message?: string) {
    super(message || "Another popup authentication is already in progress");
    this.name = "PopupInProgressError";
    Object.setPrototypeOf(this, PopupInProgressError.prototype);
  }
}

export class ExecutionContextError extends SdkError {
  public code = "invalid_execution_context" as const;

  constructor(message?: string) {
    super(message || "Method can only be called in browser context");
    this.name = "ExecutionContextError";
    Object.setPrototypeOf(this, ExecutionContextError.prototype);
  }
}
