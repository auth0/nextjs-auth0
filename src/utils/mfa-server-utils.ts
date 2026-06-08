import { NextResponse } from "next/server.js";

import type { EnrollOobOptions, EnrollOtpOptions } from "../types/index.js";

/**
 * Builds type-safe enrollment options from request body.
 * snake_case ONLY (oob_channels, phone_number), no camelCase fallback.
 *
 * @param body - Request body
 * @param authenticatorType - Type of authenticator to enroll
 * @returns Tuple of [options, null] or [null, errorResponse]
 */
export function buildEnrollOptions(
  body: unknown,
  authenticatorType: string
):
  | [Omit<EnrollOobOptions, "mfaToken">, null]
  | [Omit<EnrollOtpOptions, "mfaToken">, null]
  | [null, NextResponse] {
  const bodyObj = body as Record<string, unknown>;
  if (authenticatorType === "oob") {
    // snake_case ONLY
    const oobChannels = bodyObj.oob_channels;
    if (!oobChannels || !Array.isArray(oobChannels)) {
      return [
        null,
        NextResponse.json(
          {
            error: "invalid_request",
            error_description:
              "Missing or invalid oob_channels for OOB enrollment"
          },
          { status: 400 }
        )
      ];
    }
    const phoneNumber =
      typeof bodyObj.phone_number === "string" && bodyObj.phone_number !== ""
        ? bodyObj.phone_number
        : undefined;
    const email =
      typeof bodyObj.email === "string" && bodyObj.email !== ""
        ? bodyObj.email
        : undefined;
    return [
      {
        authenticatorTypes: ["oob"] as ["oob"],
        oobChannels: oobChannels as ("sms" | "voice" | "auth0" | "email")[],
        phoneNumber,
        email
      },
      null
    ];
  } else if (authenticatorType === "otp") {
    return [
      {
        authenticatorTypes: ["otp"] as ["otp"]
      },
      null
    ];
  } else {
    return [
      null,
      NextResponse.json(
        {
          error: "invalid_request",
          error_description: `Unsupported authenticator_type: ${authenticatorType}`
        },
        { status: 400 }
      )
    ];
  }
}
