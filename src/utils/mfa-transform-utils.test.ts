import { describe, expect, it } from "vitest";

import type { EnrollOptions } from "../types/mfa.js";
import {
  FACTOR_MAPPING,
  normalizeEnrollOptions
} from "./mfa-transform-utils.js";

describe("mfa-transform-utils", () => {
  describe("FACTOR_MAPPING", () => {
    it("should have all required factor types", () => {
      expect(FACTOR_MAPPING).toHaveProperty("otp");
      expect(FACTOR_MAPPING).toHaveProperty("sms");
      expect(FACTOR_MAPPING).toHaveProperty("voice");
      expect(FACTOR_MAPPING).toHaveProperty("email");
      expect(FACTOR_MAPPING).toHaveProperty("push");
    });

    it("should map otp to authenticator_types", () => {
      expect(FACTOR_MAPPING.otp).toEqual({
        authenticator_types: ["otp"]
      });
    });

    it("should map sms to oob with sms channel", () => {
      expect(FACTOR_MAPPING.sms).toEqual({
        authenticator_types: ["oob"],
        oob_channels: ["sms"]
      });
    });

    it("should map voice to oob with voice channel", () => {
      expect(FACTOR_MAPPING.voice).toEqual({
        authenticator_types: ["oob"],
        oob_channels: ["voice"]
      });
    });

    it("should map email to oob with email channel", () => {
      expect(FACTOR_MAPPING.email).toEqual({
        authenticator_types: ["oob"],
        oob_channels: ["email"]
      });
    });

    it("should map push to oob with auth0 channel", () => {
      expect(FACTOR_MAPPING.push).toEqual({
        authenticator_types: ["oob"],
        oob_channels: ["auth0"]
      });
    });
  });

  describe("normalizeEnrollOptions", () => {
    describe("factorType variants", () => {
      it("should normalize factorType: 'otp' to authenticatorTypes", () => {
        const result = normalizeEnrollOptions({
          mfaToken: "token123",
          factorType: "otp"
        });

        expect(result).toEqual({
          mfaToken: "token123",
          authenticatorTypes: ["otp"]
        });
      });

      it("should normalize factorType: 'sms' with phoneNumber", () => {
        const result = normalizeEnrollOptions({
          mfaToken: "token123",
          factorType: "sms",
          phoneNumber: "+15551234567"
        });

        expect(result).toEqual({
          mfaToken: "token123",
          authenticatorTypes: ["oob"],
          oobChannels: ["sms"],
          phoneNumber: "+15551234567"
        });
      });

      it("should normalize factorType: 'voice' with phoneNumber", () => {
        const result = normalizeEnrollOptions({
          mfaToken: "token123",
          factorType: "voice",
          phoneNumber: "+15551234567"
        });

        expect(result).toEqual({
          mfaToken: "token123",
          authenticatorTypes: ["oob"],
          oobChannels: ["voice"],
          phoneNumber: "+15551234567"
        });
      });

      it("should normalize factorType: 'email' with email", () => {
        const result = normalizeEnrollOptions({
          mfaToken: "token123",
          factorType: "email",
          email: "user@example.com"
        });

        expect(result).toEqual({
          mfaToken: "token123",
          authenticatorTypes: ["oob"],
          oobChannels: ["email"],
          email: "user@example.com"
        });
      });

      it("should normalize factorType: 'push' (no channels required)", () => {
        const result = normalizeEnrollOptions({
          mfaToken: "token123",
          factorType: "push"
        });

        expect(result).toEqual({
          mfaToken: "token123",
          authenticatorTypes: ["oob"],
          oobChannels: ["auth0"]
        });
      });

      it("should throw for unknown factorType", () => {
        expect(() => {
          normalizeEnrollOptions({
            mfaToken: "token123",
            factorType: "unknown" as any
          });
        }).toThrow("Unknown factorType: unknown");
      });

      it("should preserve phoneNumber and email for oob types", () => {
        const result = normalizeEnrollOptions({
          mfaToken: "token123",
          factorType: "sms",
          phoneNumber: "+15551234567",
          email: "user@example.com"
        });

        expect(result).toEqual({
          mfaToken: "token123",
          authenticatorTypes: ["oob"],
          oobChannels: ["sms"],
          phoneNumber: "+15551234567",
          email: "user@example.com"
        });
      });

      it("should not include phoneNumber if undefined", () => {
        const result = normalizeEnrollOptions({
          mfaToken: "token123",
          factorType: "sms"
        });

        expect(result).toEqual({
          mfaToken: "token123",
          authenticatorTypes: ["oob"],
          oobChannels: ["sms"]
        });
        expect("phoneNumber" in result).toBe(false);
      });

      it("should not include email if undefined", () => {
        const result = normalizeEnrollOptions({
          mfaToken: "token123",
          factorType: "email"
        });

        expect(result).toEqual({
          mfaToken: "token123",
          authenticatorTypes: ["oob"],
          oobChannels: ["email"]
        });
        expect("email" in result).toBe(false);
      });
    });

    describe("authenticatorTypes variants (passthrough)", () => {
      it("should passthrough EnrollOtpOptions unchanged", () => {
        const options: EnrollOptions = {
          mfaToken: "token123",
          authenticatorTypes: ["otp"]
        };
        const result = normalizeEnrollOptions(options);

        expect(result).toEqual(options);
      });

      it("should passthrough EnrollOobOptions unchanged", () => {
        const options: EnrollOptions = {
          mfaToken: "token123",
          authenticatorTypes: ["oob"],
          oobChannels: ["sms"],
          phoneNumber: "+15551234567"
        };
        const result = normalizeEnrollOptions(options);

        expect(result).toEqual(options);
      });

      it("should passthrough EnrollOobOptions with email unchanged", () => {
        const options: EnrollOptions = {
          mfaToken: "token123",
          authenticatorTypes: ["oob"],
          oobChannels: ["email"],
          email: "user@example.com"
        };
        const result = normalizeEnrollOptions(options);

        expect(result).toEqual(options);
      });
    });
  });
});
