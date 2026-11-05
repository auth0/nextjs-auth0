import { describe, expect, it } from "vitest";

import { PoppyError, PoppyErrorCode, SdkError } from "./index.js";

describe("PoppyError", () => {
  it("is an SdkError with a name and the given code", () => {
    const error = new PoppyError(PoppyErrorCode.INVALID_GUEST);

    expect(error).toBeInstanceOf(SdkError);
    expect(error).toBeInstanceOf(PoppyError);
    expect(error.name).toBe("PoppyError");
    expect(error.code).toBe("invalid_poppy_guest");
  });

  it.each([
    [PoppyErrorCode.INVALID_GUEST, /neither a guest nor a user/],
    [PoppyErrorCode.GUEST_NOT_SUPPORTED, /cannot complete in a popup/]
  ])("has a default message for %s", (code, message) => {
    expect(new PoppyError(code).message).toMatch(message);
  });

  it("takes a custom message", () => {
    expect(
      new PoppyError(PoppyErrorCode.INVALID_GUEST, "Reason: no act").message
    ).toBe("Reason: no act");
  });

  it("exposes stable code strings", () => {
    expect(PoppyErrorCode.INVALID_GUEST).toBe("invalid_poppy_guest");
    expect(PoppyErrorCode.GUEST_NOT_SUPPORTED).toBe(
      "poppy_guest_not_supported"
    );
  });
});
