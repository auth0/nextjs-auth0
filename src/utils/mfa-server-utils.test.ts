import { NextResponse } from "next/server.js";
import { describe, expect, it } from "vitest";

import { buildEnrollOptions } from "./mfa-server-utils.js";

describe("buildEnrollOptions", () => {
  describe("authenticatorType: oob", () => {
    it("returns 400 when oob_channels is missing", () => {
      const [opts, err] = buildEnrollOptions({}, "oob");

      expect(opts).toBeNull();
      expect(err).toBeInstanceOf(NextResponse);
      expect(err!.status).toBe(400);
    });

    it("returns 400 when oob_channels is not an array", () => {
      const [opts, err] = buildEnrollOptions({ oob_channels: "sms" }, "oob");

      expect(opts).toBeNull();
      expect(err).toBeInstanceOf(NextResponse);
      expect(err!.status).toBe(400);
    });

    it("returns oob options with authenticatorTypes and oobChannels when valid", () => {
      const [opts, err] = buildEnrollOptions({ oob_channels: ["sms"] }, "oob");

      expect(err).toBeNull();
      expect(opts).toMatchObject({
        authenticatorTypes: ["oob"],
        oobChannels: ["sms"]
      });
    });

    it("includes phone_number when provided as a non-empty string", () => {
      const [opts, err] = buildEnrollOptions(
        { oob_channels: ["sms"], phone_number: "+15551234567" },
        "oob"
      );

      expect(err).toBeNull();
      expect(opts).toMatchObject({
        phoneNumber: "+15551234567"
      });
    });

    it("sets phoneNumber to undefined when phone_number is an empty string", () => {
      const [opts, err] = buildEnrollOptions(
        { oob_channels: ["sms"], phone_number: "" },
        "oob"
      );

      expect(err).toBeNull();
      expect(opts).toMatchObject({ phoneNumber: undefined });
    });

    it("sets phoneNumber to undefined when phone_number is not a string", () => {
      const [opts, err] = buildEnrollOptions(
        { oob_channels: ["sms"], phone_number: 12345 },
        "oob"
      );

      expect(err).toBeNull();
      expect(opts).toMatchObject({ phoneNumber: undefined });
    });

    it("includes email when provided as a non-empty string", () => {
      const [opts, err] = buildEnrollOptions(
        { oob_channels: ["email"], email: "user@example.com" },
        "oob"
      );

      expect(err).toBeNull();
      expect(opts).toMatchObject({
        email: "user@example.com"
      });
    });

    it("sets email to undefined when email is an empty string", () => {
      const [opts, err] = buildEnrollOptions(
        { oob_channels: ["email"], email: "" },
        "oob"
      );

      expect(err).toBeNull();
      expect(opts).toMatchObject({ email: undefined });
    });

    it("sets email to undefined when email is not a string", () => {
      const [opts, err] = buildEnrollOptions(
        { oob_channels: ["email"], email: 42 },
        "oob"
      );

      expect(err).toBeNull();
      expect(opts).toMatchObject({ email: undefined });
    });

    it("includes both phone_number and email when both provided", () => {
      const [opts, err] = buildEnrollOptions(
        {
          oob_channels: ["sms", "email"],
          phone_number: "+15551234567",
          email: "user@example.com"
        },
        "oob"
      );

      expect(err).toBeNull();
      expect(opts).toMatchObject({
        oobChannels: ["sms", "email"],
        phoneNumber: "+15551234567",
        email: "user@example.com"
      });
    });

    it("omits phone_number and email when neither is provided", () => {
      const [opts, err] = buildEnrollOptions(
        { oob_channels: ["auth0"] },
        "oob"
      );

      expect(err).toBeNull();
      expect(opts).toMatchObject({
        authenticatorTypes: ["oob"],
        oobChannels: ["auth0"],
        phoneNumber: undefined,
        email: undefined
      });
    });
  });

  describe("authenticatorType: otp", () => {
    it("returns otp options with authenticatorTypes", () => {
      const [opts, err] = buildEnrollOptions({}, "otp");

      expect(err).toBeNull();
      expect(opts).toEqual({
        authenticatorTypes: ["otp"]
      });
    });

    it("ignores any extra body fields", () => {
      const [opts, err] = buildEnrollOptions(
        { phone_number: "+15551234567", oob_channels: ["sms"] },
        "otp"
      );

      expect(err).toBeNull();
      expect(opts).toEqual({ authenticatorTypes: ["otp"] });
    });
  });

  describe("authenticatorType: unsupported", () => {
    it("returns 400 for an unknown authenticator type", async () => {
      const [opts, err] = buildEnrollOptions({}, "totp");

      expect(opts).toBeNull();
      expect(err).toBeInstanceOf(NextResponse);
      expect(err!.status).toBe(400);

      const body = await err!.json();
      expect(body.error).toBe("invalid_request");
      expect(body.error_description).toContain("totp");
    });

    it("returns 400 for empty string authenticator type", async () => {
      const [opts, err] = buildEnrollOptions({}, "");

      expect(opts).toBeNull();
      expect(err).toBeInstanceOf(NextResponse);
      expect(err!.status).toBe(400);
    });
  });
});
