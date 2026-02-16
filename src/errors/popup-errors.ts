import { SdkError } from "./sdk-error.js";

/**
 * Thrown when the browser blocks the popup window opened by {@link mfa.stepUpWithPopup}.
 *
 * Most browsers block popups unless they are triggered by a direct user action
 * (e.g., a click handler). Prompt the user to allow popups for your site.
 *
 * @example
 * ```typescript
 * import { PopupBlockedError } from '@auth0/nextjs-auth0/errors';
 *
 * try {
 *   await mfa.stepUpWithPopup({ audience: 'https://api.example.com' });
 * } catch (err) {
 *   if (err instanceof PopupBlockedError) {
 *     alert('Please allow popups for this site.');
 *   }
 * }
 * ```
 */
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

/**
 * Thrown when the user closes the popup window before completing MFA.
 *
 * The SDK polls `popup.closed` every 500ms to detect manual closure.
 * This is a user-initiated cancellation, not an error condition.
 *
 * @example
 * ```typescript
 * import { PopupCancelledError } from '@auth0/nextjs-auth0/errors';
 *
 * try {
 *   await mfa.stepUpWithPopup({ audience: 'https://api.example.com' });
 * } catch (err) {
 *   if (err instanceof PopupCancelledError) {
 *     console.log('User cancelled MFA.');
 *   }
 * }
 * ```
 */
export class PopupCancelledError extends SdkError {
  public code = "popup_cancelled" as const;

  constructor(message?: string) {
    super(message || "Popup was closed by user");
    this.name = "PopupCancelledError";
    Object.setPrototypeOf(this, PopupCancelledError.prototype);
  }
}

/**
 * Thrown when the popup does not complete authentication within the configured timeout.
 *
 * Default timeout is 60 seconds. Configure per-call via
 * `StepUpWithPopupOptions.timeout`.
 *
 * @example
 * ```typescript
 * import { PopupTimeoutError } from '@auth0/nextjs-auth0/errors';
 *
 * try {
 *   await mfa.stepUpWithPopup({ audience: 'https://api.example.com', timeout: 120000 });
 * } catch (err) {
 *   if (err instanceof PopupTimeoutError) {
 *     console.log('MFA timed out. Please try again.');
 *   }
 * }
 * ```
 */
export class PopupTimeoutError extends SdkError {
  public code = "popup_timeout" as const;

  constructor(message?: string) {
    super(message || "Popup did not complete within timeout");
    this.name = "PopupTimeoutError";
    Object.setPrototypeOf(this, PopupTimeoutError.prototype);
  }
}

/**
 * Thrown when {@link mfa.stepUpWithPopup} is called while another popup is already active.
 *
 * Only one popup flow is allowed at a time, regardless of audience. Wait for the
 * current popup to complete or be cancelled before starting another.
 *
 * @example
 * ```typescript
 * import { PopupInProgressError } from '@auth0/nextjs-auth0/errors';
 *
 * try {
 *   await mfa.stepUpWithPopup({ audience: 'https://api.example.com' });
 * } catch (err) {
 *   if (err instanceof PopupInProgressError) {
 *     console.log('Complete the current MFA prompt first.');
 *   }
 * }
 * ```
 */
export class PopupInProgressError extends SdkError {
  public code = "popup_in_progress" as const;

  constructor(message?: string) {
    super(message || "Another popup authentication is already in progress");
    this.name = "PopupInProgressError";
    Object.setPrototypeOf(this, PopupInProgressError.prototype);
  }
}

/**
 * Thrown when {@link mfa.stepUpWithPopup} is called outside of a browser context
 * (e.g., in a Server Component, Route Handler, or middleware).
 *
 * `stepUpWithPopup()` requires `window` and can only run in client components.
 *
 * @example
 * ```typescript
 * import { ExecutionContextError } from '@auth0/nextjs-auth0/errors';
 *
 * try {
 *   await mfa.stepUpWithPopup({ audience: 'https://api.example.com' });
 * } catch (err) {
 *   if (err instanceof ExecutionContextError) {
 *     // This method must be called from a client component
 *   }
 * }
 * ```
 */
export class ExecutionContextError extends SdkError {
  public code = "invalid_execution_context" as const;

  constructor(message?: string) {
    super(message || "Method can only be called in browser context");
    this.name = "ExecutionContextError";
    Object.setPrototypeOf(this, ExecutionContextError.prototype);
  }
}
