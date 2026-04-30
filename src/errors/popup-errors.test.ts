import { describe, expect, it } from "vitest";

import {
  ExecutionContextError,
  PopupBlockedError,
  PopupCancelledError,
  PopupInProgressError,
  PopupTimeoutError
} from "./popup-errors.js";
import { SdkError } from "./sdk-error.js";

describe("Popup Error Classes", () => {
  describe("PopupBlockedError", () => {
    it("should have correct code and default message", () => {
      const error = new PopupBlockedError();
      expect(error.code).toBe("popup_blocked");
      expect(error.name).toBe("PopupBlockedError");
      expect(error.message).toBe(
        "Popup was blocked by browser. Enable popups for this site."
      );
    });

    it("should accept custom message", () => {
      const error = new PopupBlockedError("Custom blocked msg");
      expect(error.message).toBe("Custom blocked msg");
      expect(error.code).toBe("popup_blocked");
    });

    it("should be instanceof SdkError and Error", () => {
      const error = new PopupBlockedError();
      expect(error).toBeInstanceOf(PopupBlockedError);
      expect(error).toBeInstanceOf(SdkError);
      expect(error).toBeInstanceOf(Error);
    });
  });

  describe("PopupCancelledError", () => {
    it("should have correct code and default message", () => {
      const error = new PopupCancelledError();
      expect(error.code).toBe("popup_cancelled");
      expect(error.name).toBe("PopupCancelledError");
      expect(error.message).toBe("Popup was closed by user");
    });

    it("should accept custom message", () => {
      const error = new PopupCancelledError("User closed it");
      expect(error.message).toBe("User closed it");
    });

    it("should be instanceof SdkError and Error", () => {
      const error = new PopupCancelledError();
      expect(error).toBeInstanceOf(PopupCancelledError);
      expect(error).toBeInstanceOf(SdkError);
      expect(error).toBeInstanceOf(Error);
    });
  });

  describe("PopupTimeoutError", () => {
    it("should have correct code and default message", () => {
      const error = new PopupTimeoutError();
      expect(error.code).toBe("popup_timeout");
      expect(error.name).toBe("PopupTimeoutError");
      expect(error.message).toBe("Popup did not complete within timeout");
    });

    it("should accept custom message", () => {
      const error = new PopupTimeoutError("Took too long");
      expect(error.message).toBe("Took too long");
    });

    it("should be instanceof SdkError and Error", () => {
      const error = new PopupTimeoutError();
      expect(error).toBeInstanceOf(PopupTimeoutError);
      expect(error).toBeInstanceOf(SdkError);
      expect(error).toBeInstanceOf(Error);
    });
  });

  describe("PopupInProgressError", () => {
    it("should have correct code and default message", () => {
      const error = new PopupInProgressError();
      expect(error.code).toBe("popup_in_progress");
      expect(error.name).toBe("PopupInProgressError");
      expect(error.message).toBe(
        "Another popup authentication is already in progress"
      );
    });

    it("should accept custom message", () => {
      const error = new PopupInProgressError("Already running");
      expect(error.message).toBe("Already running");
    });

    it("should be instanceof SdkError and Error", () => {
      const error = new PopupInProgressError();
      expect(error).toBeInstanceOf(PopupInProgressError);
      expect(error).toBeInstanceOf(SdkError);
      expect(error).toBeInstanceOf(Error);
    });
  });

  describe("ExecutionContextError", () => {
    it("should have correct code and default message", () => {
      const error = new ExecutionContextError();
      expect(error.code).toBe("invalid_execution_context");
      expect(error.name).toBe("ExecutionContextError");
      expect(error.message).toBe(
        "Method can only be called in browser context"
      );
    });

    it("should accept custom message", () => {
      const error = new ExecutionContextError("Not in browser");
      expect(error.message).toBe("Not in browser");
    });

    it("should be instanceof SdkError and Error", () => {
      const error = new ExecutionContextError();
      expect(error).toBeInstanceOf(ExecutionContextError);
      expect(error).toBeInstanceOf(SdkError);
      expect(error).toBeInstanceOf(Error);
    });
  });

  describe("Error discrimination", () => {
    it("should distinguish between different popup error types", () => {
      const errors = [
        new PopupBlockedError(),
        new PopupCancelledError(),
        new PopupTimeoutError(),
        new PopupInProgressError(),
        new ExecutionContextError()
      ];

      // Each should only be instanceof its own class
      expect(errors[0]).toBeInstanceOf(PopupBlockedError);
      expect(errors[0]).not.toBeInstanceOf(PopupCancelledError);

      expect(errors[1]).toBeInstanceOf(PopupCancelledError);
      expect(errors[1]).not.toBeInstanceOf(PopupTimeoutError);

      expect(errors[2]).toBeInstanceOf(PopupTimeoutError);
      expect(errors[2]).not.toBeInstanceOf(PopupInProgressError);

      expect(errors[3]).toBeInstanceOf(PopupInProgressError);
      expect(errors[3]).not.toBeInstanceOf(ExecutionContextError);

      expect(errors[4]).toBeInstanceOf(ExecutionContextError);
      expect(errors[4]).not.toBeInstanceOf(PopupBlockedError);
    });

    it("should have unique error codes", () => {
      const codes = [
        new PopupBlockedError().code,
        new PopupCancelledError().code,
        new PopupTimeoutError().code,
        new PopupInProgressError().code,
        new ExecutionContextError().code
      ];

      expect(new Set(codes).size).toBe(5);
    });
  });
});
