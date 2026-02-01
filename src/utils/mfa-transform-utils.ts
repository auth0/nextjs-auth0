import { NextResponse } from "next/server.js";

import type {
  Authenticator,
  ChallengeResponse,
  EnrollEmailOptions,
  EnrollmentResponse,
  EnrollOobOptions,
  EnrollOtpOptions
} from "../types/index.js";
import type {
  AuthenticatorApiResponse,
  ChallengeApiResponse,
  EnrollmentApiResponse
} from "../types/mfa.js";

/**
 * Transforms Auth0 API authenticator response (snake_case) to SDK format (camelCase).
 *
 * @param auth - Raw authenticator from Auth0 API
 * @returns Transformed authenticator
 */
export function camelizeAuthenticator(
  auth: AuthenticatorApiResponse
): Authenticator {
  return {
    id: auth.id,
    authenticatorType: auth.authenticator_type,
    type: auth.type,
    active: auth.active,
    name: auth.name,
    phoneNumber: auth.phone_number,
    oobChannel: auth.oob_channel,
    createdAt: auth.created_at,
    lastAuthenticatedAt: auth.last_auth
  };
}

/**
 * Transforms Auth0 API challenge response (snake_case) to SDK format (camelCase).
 *
 * @param result - Raw challenge result from Auth0 API
 * @returns Transformed challenge response
 */
export function camelizeChallengeResponse(
  result: ChallengeApiResponse
): ChallengeResponse {
  return {
    challengeType: result.challenge_type,
    oobCode: result.oob_code,
    bindingMethod: result.binding_method
  };
}

/**
 * Transforms Auth0 API enrollment response (snake_case) to SDK format (camelCase).
 * Builds discriminated union based on authenticator type.
 *
 * @param result - Raw enrollment result from Auth0 API
 * @returns Transformed enrollment response
 */
export function buildEnrollmentResponse(
  result: EnrollmentApiResponse
): EnrollmentResponse {
  const baseResponse = {
    authenticatorType: result.authenticator_type,
    id: result.id,
    recoveryCodes: result.recovery_codes
  };

  if (result.authenticator_type === "otp") {
    return {
      ...baseResponse,
      authenticatorType: "otp" as const,
      secret: result.secret!,
      barcodeUri: result.barcode_uri!
    };
  } else if (result.authenticator_type === "oob") {
    return {
      ...baseResponse,
      authenticatorType: "oob" as const,
      oobChannel: result.oob_channel!,
      name: result.name
    };
  } else {
    // email
    return {
      ...baseResponse,
      authenticatorType: "email" as const,
      name: result.name
    };
  }
}

/**
 * Builds type-safe enrollment options from request body.
 * Validates type-specific required fields.
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
  | [Omit<EnrollEmailOptions, "mfaToken">, null]
  | [Omit<EnrollOtpOptions, "mfaToken">, null]
  | [null, NextResponse] {
  const bodyObj = body as Record<string, unknown>;
  if (authenticatorType === "oob") {
    if (!bodyObj.oobChannels || !Array.isArray(bodyObj.oobChannels)) {
      return [
        null,
        NextResponse.json(
          {
            error: "invalid_request",
            error_description:
              "Missing or invalid oobChannels for OOB enrollment"
          },
          { status: 400 }
        )
      ];
    }
    const phoneNumber =
      typeof bodyObj.phoneNumber === "string" && bodyObj.phoneNumber !== ""
        ? bodyObj.phoneNumber
        : undefined;
    return [
      {
        authenticatorTypes: ["oob"] as ["oob"],
        oobChannels: bodyObj.oobChannels as ("sms" | "voice" | "auth0")[],
        phoneNumber
      },
      null
    ];
  } else if (authenticatorType === "email") {
    const email =
      typeof bodyObj.email === "string" && bodyObj.email !== ""
        ? bodyObj.email
        : undefined;
    return [
      {
        authenticatorTypes: ["email"] as ["email"],
        email
      },
      null
    ];
  } else {
    // otp
    return [
      {
        authenticatorTypes: ["otp"] as ["otp"]
      },
      null
    ];
  }
}
