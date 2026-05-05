import {
  PopupCancelledError,
  PopupTimeoutError
} from "../errors/popup-errors.js";
import { POLL_INTERVAL } from "./constants.js";

export {
  AUTO_CLOSE_DELAY,
  DEFAULT_POPUP_HEIGHT,
  DEFAULT_POPUP_TIMEOUT,
  DEFAULT_POPUP_WIDTH,
  POLL_INTERVAL
} from "./constants.js";

/**
 * postMessage payload sent from the popup callback page to the parent window.
 *
 * Uses a discriminated union on `success` for type-safe handling:
 * - `success: true` — MFA completed, optional user metadata attached
 * - `success: false` — error occurred, error code and message attached
 *
 * Security: Never contains raw access tokens. Only user metadata (`sub`, `email`)
 * is sent via postMessage. Tokens remain server-side in the encrypted session.
 */
export type AuthCompleteMessage =
  | {
      type: "auth_complete";
      success: true;
      /** User metadata from the authenticated session (sub and email only). */
      user?: { sub: string; email: string };
    }
  | {
      type: "auth_complete";
      success: false;
      /** Error details from the callback (OAuth error code + description). */
      error: { code: string; message: string };
    };

/**
 * Opens a centered popup window.
 * @param url - URL to open in popup
 * @param width - Popup width (pixels)
 * @param height - Popup height (pixels)
 * @returns Window reference or null if blocked
 */
export function openCenteredPopup(
  url: string,
  width: number,
  height: number
): Window | null {
  const left = window.screenX + (window.outerWidth - width) / 2;
  const top = window.screenY + (window.outerHeight - height) / 2;

  return window.open(
    url,
    "_blank",
    `width=${width},height=${height},left=${left},top=${top},scrollbars=yes`
  );
}

/**
 * Waits for popup to complete authentication via postMessage.
 *
 * Monitors three conditions concurrently:
 * 1. **postMessage** with `type: 'auth_complete'` from same origin (resolves)
 * 2. **popup.closed** polling every {@link POLL_INTERVAL}ms (rejects)
 * 3. **Timeout** expiry (rejects)
 *
 * Only accepts messages where `event.origin === window.location.origin`
 * (same-origin validation, Design Decision DD-1).
 *
 * @param popup - Popup window reference from `window.open()`
 * @param timeout - Timeout in milliseconds before rejecting
 * @returns Promise resolving to {@link AuthCompleteMessage}
 * @throws {PopupTimeoutError} If timeout expires before completion
 * @throws {PopupCancelledError} If user closes popup before completion
 */
export function waitForPopupCompletion(
  popup: Window,
  timeout: number
): Promise<AuthCompleteMessage> {
  return new Promise<AuthCompleteMessage>((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      cleanup();
      reject(
        new PopupTimeoutError(`Popup did not complete within ${timeout}ms`)
      );
    }, timeout);

    const pollId = setInterval(() => {
      if (popup.closed) {
        cleanup();
        reject(new PopupCancelledError("Popup was closed by user"));
      }
    }, POLL_INTERVAL);

    function messageHandler(event: MessageEvent) {
      if (event.origin !== window.location.origin) {
        return; // Ignore cross-origin messages
      }

      if (event.data?.type === "auth_complete") {
        cleanup();
        resolve(event.data as AuthCompleteMessage);
      }
    }

    function cleanup() {
      clearTimeout(timeoutId);
      clearInterval(pollId);
      window.removeEventListener("message", messageHandler);
    }

    window.addEventListener("message", messageHandler);
  });
}
