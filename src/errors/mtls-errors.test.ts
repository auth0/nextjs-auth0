import { describe, expect, it } from "vitest";

import { SdkError } from "../errors/index.js";
import { MtlsError, MtlsErrorCode } from "./mtls-errors.js";

describe("MtlsError", () => {
  it("is an instance of SdkError", () => {
    const error = new MtlsError(
      MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
      "useMtls requires a customFetch option."
    );
    expect(error).toBeInstanceOf(SdkError);
    expect(error).toBeInstanceOf(Error);
  });

  it("sets name to MtlsError", () => {
    const error = new MtlsError(
      MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
      "some message"
    );
    expect(error.name).toBe("MtlsError");
  });

  it("sets code from the enum value", () => {
    const error = new MtlsError(
      MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
      "some message"
    );
    expect(error.code).toBe("mtls_requires_custom_fetch");
    expect(error.code).toBe(MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH);
  });

  it("sets message correctly", () => {
    const message =
      "useMtls requires a customFetch option with a TLS client certificate.";
    const error = new MtlsError(
      MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
      message
    );
    expect(error.message).toBe(message);
  });

  it("is catchable by error.code without instanceof", () => {
    const error = new MtlsError(
      MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
      "some message"
    );
    // The SDK pattern is to catch by error.code, not instanceof
    expect(error.code).toBe(MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH);
  });

  it("is exported from the errors index", async () => {
    const { MtlsError: IndexedMtlsError, MtlsErrorCode: IndexedMtlsErrorCode } =
      await import("./index.js");
    expect(IndexedMtlsError).toBeDefined();
    expect(IndexedMtlsErrorCode).toBeDefined();
    expect(IndexedMtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH).toBe(
      "mtls_requires_custom_fetch"
    );
  });
});

describe("MtlsErrorCode", () => {
  it("has the MTLS_REQUIRES_CUSTOM_FETCH code", () => {
    expect(MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH).toBe(
      "mtls_requires_custom_fetch"
    );
  });
});
