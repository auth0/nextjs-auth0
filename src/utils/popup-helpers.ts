import {
  PopupCancelledError,
  PopupTimeoutError
} from "../errors/popup-errors.js";

/**
 * postMessage payload (discriminated union)
 */
export type AuthCompleteMessage =
  | {
      type: "auth_complete";
      success: true;
      user?: { sub: string; email: string };
    }
  | {
      type: "auth_complete";
      success: false;
      error: { code: string; message: string };
    };

export const DEFAULT_POPUP_WIDTH = 400;
export const DEFAULT_POPUP_HEIGHT = 600;
export const DEFAULT_POPUP_TIMEOUT = 60000;
export const AUTO_CLOSE_DELAY = 2000;
export const POLL_INTERVAL = 500;

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
 * Monitors for:
 *   - postMessage with type 'auth_complete' from same origin (resolve)
 *   - popup.closed === true (reject PopupCancelledError)
 *   - timeout expiry (reject PopupTimeoutError)
 *
 * @param popup - Popup window reference
 * @param timeout - Timeout in milliseconds
 * @returns Promise resolving to AuthCompleteMessage
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
