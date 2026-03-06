/**
 * @vitest-environment jsdom
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  PopupCancelledError,
  PopupTimeoutError
} from "../errors/popup-errors.js";
import {
  AUTO_CLOSE_DELAY,
  DEFAULT_POPUP_HEIGHT,
  DEFAULT_POPUP_TIMEOUT,
  DEFAULT_POPUP_WIDTH,
  openCenteredPopup,
  POLL_INTERVAL,
  waitForPopupCompletion
} from "./popup-helpers.js";

describe("popup-helpers", () => {
  describe("constants", () => {
    it("should export correct default values", () => {
      expect(DEFAULT_POPUP_WIDTH).toBe(400);
      expect(DEFAULT_POPUP_HEIGHT).toBe(600);
      expect(DEFAULT_POPUP_TIMEOUT).toBe(60000);
      expect(AUTO_CLOSE_DELAY).toBe(2000);
      expect(POLL_INTERVAL).toBe(500);
    });
  });

  describe("openCenteredPopup", () => {
    let openSpy: any;

    beforeEach(() => {
      openSpy = vi.spyOn(window, "open");
    });

    afterEach(() => {
      openSpy.mockRestore();
    });

    it("should call window.open with centered coordinates", () => {
      // Mock window dimensions
      Object.defineProperty(window, "screenX", { value: 100, writable: true });
      Object.defineProperty(window, "screenY", { value: 50, writable: true });
      Object.defineProperty(window, "outerWidth", {
        value: 1200,
        writable: true
      });
      Object.defineProperty(window, "outerHeight", {
        value: 800,
        writable: true
      });

      const mockPopup = { closed: false } as Window;
      openSpy.mockReturnValue(mockPopup);

      const result = openCenteredPopup("https://example.com", 400, 600);

      expect(result).toBe(mockPopup);
      expect(openSpy).toHaveBeenCalledWith(
        "https://example.com",
        "_blank",
        expect.stringContaining("width=400")
      );
      expect(openSpy).toHaveBeenCalledWith(
        "https://example.com",
        "_blank",
        expect.stringContaining("height=600")
      );

      // Check centered positioning: left = 100 + (1200 - 400) / 2 = 500
      // top = 50 + (800 - 600) / 2 = 150
      const features = openSpy.mock.calls[0][2] as string;
      expect(features).toContain("left=500");
      expect(features).toContain("top=150");
      expect(features).toContain("scrollbars=yes");
    });

    it("should return null when popup is blocked", () => {
      openSpy.mockReturnValue(null);

      const result = openCenteredPopup("https://example.com", 400, 600);

      expect(result).toBeNull();
    });

    it("should use custom dimensions", () => {
      const mockPopup = { closed: false } as Window;
      openSpy.mockReturnValue(mockPopup);

      openCenteredPopup("https://example.com", 800, 1000);

      const features = openSpy.mock.calls[0][2] as string;
      expect(features).toContain("width=800");
      expect(features).toContain("height=1000");
    });
  });

  describe("waitForPopupCompletion", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("should resolve on valid auth_complete postMessage from same origin", async () => {
      const mockPopup = { closed: false } as Window;

      const promise = waitForPopupCompletion(mockPopup, 60000);

      // Simulate postMessage from same origin
      const messageEvent = new MessageEvent("message", {
        data: {
          type: "auth_complete",
          success: true,
          user: { sub: "auth0|123", email: "test@example.com" }
        },
        origin: window.location.origin
      });
      window.dispatchEvent(messageEvent);

      const result = await promise;
      expect(result).toEqual({
        type: "auth_complete",
        success: true,
        user: { sub: "auth0|123", email: "test@example.com" }
      });
    });

    it("should resolve on error auth_complete postMessage", async () => {
      const mockPopup = { closed: false } as Window;

      const promise = waitForPopupCompletion(mockPopup, 60000);

      const messageEvent = new MessageEvent("message", {
        data: {
          type: "auth_complete",
          success: false,
          error: { code: "access_denied", message: "User denied" }
        },
        origin: window.location.origin
      });
      window.dispatchEvent(messageEvent);

      const result = await promise;
      expect(result).toEqual({
        type: "auth_complete",
        success: false,
        error: { code: "access_denied", message: "User denied" }
      });
    });

    it("should ignore messages from different origin", async () => {
      const mockPopup = { closed: false } as Window;

      const promise = waitForPopupCompletion(mockPopup, 1000);
      // Attach catch handler immediately to avoid unhandled rejection
      const rejection =
        expect(promise).rejects.toBeInstanceOf(PopupTimeoutError);

      // Simulate cross-origin message
      const crossOriginEvent = new MessageEvent("message", {
        data: { type: "auth_complete", success: true },
        origin: "https://evil.com"
      });
      window.dispatchEvent(crossOriginEvent);

      // Should not resolve — advance timers to timeout
      await vi.advanceTimersByTimeAsync(1000);

      await rejection;
    });

    it("should ignore messages without auth_complete type", async () => {
      const mockPopup = { closed: false } as Window;

      const promise = waitForPopupCompletion(mockPopup, 1000);
      const rejection =
        expect(promise).rejects.toBeInstanceOf(PopupTimeoutError);

      // Dispatch unrelated message from same origin
      const unrelatedEvent = new MessageEvent("message", {
        data: { type: "other_event", payload: "test" },
        origin: window.location.origin
      });
      window.dispatchEvent(unrelatedEvent);

      await vi.advanceTimersByTimeAsync(1000);

      await rejection;
    });

    it("should reject with PopupTimeoutError after timeout", async () => {
      const mockPopup = { closed: false } as Window;

      const promise = waitForPopupCompletion(mockPopup, 5000);
      const rejection = promise.catch((e) => e);

      await vi.advanceTimersByTimeAsync(5000);

      const error = await rejection;
      expect(error).toBeInstanceOf(PopupTimeoutError);
      expect(error.message).toBe("Popup did not complete within 5000ms");
    });

    it("should reject with PopupCancelledError when popup is closed", async () => {
      const mockPopup = { closed: false } as Window;

      const promise = waitForPopupCompletion(mockPopup, 60000);
      const rejection = promise.catch((e) => e);

      // Simulate popup closing
      Object.defineProperty(mockPopup, "closed", { value: true });

      // Advance past poll interval
      await vi.advanceTimersByTimeAsync(POLL_INTERVAL);

      const error = await rejection;
      expect(error).toBeInstanceOf(PopupCancelledError);
      expect(error.message).toBe("Popup was closed by user");
    });

    it("should clean up event listener and timers on success", async () => {
      const mockPopup = { closed: false } as Window;
      const removeListenerSpy = vi.spyOn(window, "removeEventListener");

      const promise = waitForPopupCompletion(mockPopup, 60000);

      const messageEvent = new MessageEvent("message", {
        data: { type: "auth_complete", success: true },
        origin: window.location.origin
      });
      window.dispatchEvent(messageEvent);

      await promise;

      expect(removeListenerSpy).toHaveBeenCalledWith(
        "message",
        expect.any(Function)
      );

      removeListenerSpy.mockRestore();
    });

    it("should clean up event listener and timers on timeout", async () => {
      const mockPopup = { closed: false } as Window;
      const removeListenerSpy = vi.spyOn(window, "removeEventListener");

      const promise = waitForPopupCompletion(mockPopup, 1000);
      const rejection = promise.catch(() => {});

      await vi.advanceTimersByTimeAsync(1000);
      await rejection;

      expect(removeListenerSpy).toHaveBeenCalledWith(
        "message",
        expect.any(Function)
      );

      removeListenerSpy.mockRestore();
    });

    it("should clean up event listener and timers on cancel", async () => {
      const mockPopup = { closed: false } as Window;
      const removeListenerSpy = vi.spyOn(window, "removeEventListener");

      const promise = waitForPopupCompletion(mockPopup, 60000);
      const rejection = promise.catch(() => {});

      Object.defineProperty(mockPopup, "closed", { value: true });
      await vi.advanceTimersByTimeAsync(POLL_INTERVAL);
      await rejection;

      expect(removeListenerSpy).toHaveBeenCalledWith(
        "message",
        expect.any(Function)
      );

      removeListenerSpy.mockRestore();
    });

    it("should accept message with undefined user on success", async () => {
      const mockPopup = { closed: false } as Window;

      const promise = waitForPopupCompletion(mockPopup, 60000);

      const messageEvent = new MessageEvent("message", {
        data: { type: "auth_complete", success: true },
        origin: window.location.origin
      });
      window.dispatchEvent(messageEvent);

      const result = await promise;
      expect(result.success).toBe(true);
    });
  });
});
