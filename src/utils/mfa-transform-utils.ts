import { NextResponse } from "next/server.js";

import { InvalidRequestError, MfaVerifyError } from "../errors/mfa-errors.js";
import type {
  Authenticator,
  ChallengeResponse,
  EnrollmentResponse,
  EnrollOobOptions,
  EnrollOptions,
  EnrollOtpOptions
} from "../types/index.js";
import {
  GRANT_TYPE_MFA_OOB,
  GRANT_TYPE_MFA_OTP,
  GRANT_TYPE_MFA_RECOVERY_CODE,
  VerifyMfaOptions,
  type AuthenticatorApiResponse,
  type ChallengeApiResponse,
  type EnrollmentApiResponse
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
    const response = {
      ...baseResponse,
      authenticatorType: "otp" as const,
      secret: result.secret!,
      barcodeUri: result.barcode_uri!
    };
    return response;
  } else if (result.authenticator_type === "oob") {
    return {
      ...baseResponse,
      authenticatorType: "oob" as const,
      oobChannel: result.oob_channel!,
      name: result.name,
      oobCode: result.oob_code,
      bindingMethod: result.binding_method,
      barcodeUri: result.barcode_uri
    };
  }

  throw new Error(`Unknown authenticator type: ${result.authenticator_type}`);
}

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

/**
 * Transforms wire-format verify body (snake_case) to SDK options (camelCase).
 * Accepts snake_case ONLY. No camelCase fallback.
 *
 * @param body - Request body with snake_case fields (otp, oob_code+binding_code, recovery_code)
 * @returns SDK options with camelCase fields
 * @throws {InvalidRequestError} If no valid credential present or camelCase fields used
 */
export function transformVerifyBodyToOptions(
  body: Record<string, any>
): Omit<VerifyMfaOptions, "mfaToken"> {
  if (body.otp) {
    return { otp: body.otp };
  }
  if (body.oob_code && body.binding_code) {
    return { oobCode: body.oob_code, bindingCode: body.binding_code };
  }
  if (body.recovery_code) {
    return { recoveryCode: body.recovery_code };
  }
  throw new InvalidRequestError("Missing verification credential");
}

export const buildVerifyParams = (
  options: VerifyMfaOptions,
  mfaToken: string
): URLSearchParams => {
  const params = new URLSearchParams();
  params.append("mfa_token", mfaToken);

  if ("otp" in options && options.otp) {
    params.append("otp", options.otp);
  } else if (
    "oobCode" in options &&
    "bindingCode" in options &&
    options.oobCode &&
    options.bindingCode
  ) {
    params.append("oob_code", options.oobCode);
    params.append("binding_code", options.bindingCode);
  } else if ("recoveryCode" in options && options.recoveryCode) {
    params.append("recovery_code", options.recoveryCode);
  } else {
    throw new MfaVerifyError(
      "invalid_request",
      "At least one verification credential required (otp, oobCode+bindingCode, or recoveryCode)"
    );
  }

  return params;
};

export const getVerifyGrantType = (params: URLSearchParams) => {
  if (params.has("otp")) {
    return GRANT_TYPE_MFA_OTP;
  } else if (params.has("oob_code") && params.has("binding_code")) {
    return GRANT_TYPE_MFA_OOB;
  } else if (params.has("recovery_code")) {
    return GRANT_TYPE_MFA_RECOVERY_CODE;
  } else {
    throw new MfaVerifyError(
      "invalid_request",
      "No verification credential provided"
    );
  }
};

/**
 * Maps factor types to authenticator types and OOB channels.
 * Used by normalizeEnrollOptions to transform factorType variants.
 */
export const FACTOR_MAPPING: Record<
  string,
  { authenticator_types: string[]; oob_channels?: string[] }
> = {
  otp: { authenticator_types: ["otp"] },
  sms: { authenticator_types: ["oob"], oob_channels: ["sms"] },
  voice: { authenticator_types: ["oob"], oob_channels: ["voice"] },
  email: { authenticator_types: ["oob"], oob_channels: ["email"] },
  push: { authenticator_types: ["oob"], oob_channels: ["auth0"] }
};

/**
 * Normalizes EnrollOptions with factorType to standard authenticatorTypes format.
 * Transforms factorType variants to their corresponding authenticatorTypes and oobChannels.
 * Passes through existing authenticatorTypes format unchanged.
 *
 * @param options - Enrollment options (factorType or authenticatorTypes variant)
 * @returns Normalized enrollment options in authenticatorTypes format
 * @throws {Error} If factorType is unknown
 *
 * @example
 * ```typescript
 * // factorType variant
 * const result1 = normalizeEnrollOptions({
 *   mfaToken: 'token123',
 *   factorType: 'sms',
 *   phoneNumber: '+15551234567'
 * });
 * // Returns: { mfaToken, authenticatorTypes: ['oob'], oobChannels: ['sms'], phoneNumber }
 *
 * // authenticatorTypes variant (passthrough)
 * const result2 = normalizeEnrollOptions({
 *   mfaToken: 'token123',
 *   authenticatorTypes: ['otp']
 * });
 * // Returns unchanged
 * ```
 */
export function normalizeEnrollOptions(
  options: EnrollOptions
): EnrollOobOptions | EnrollOtpOptions {
  if ("factorType" in options) {
    const mapping = FACTOR_MAPPING[options.factorType];
    if (!mapping) throw new InvalidRequestError(`Unknown factorType: ${options.factorType}`);

    if ((options.factorType === "sms" || options.factorType === "voice") && !("phoneNumber" in options && options.phoneNumber)) {
      throw new InvalidRequestError(`phoneNumber is required for factorType: ${options.factorType}`);
    }

    const result: any = {
      mfaToken: options.mfaToken,
      authenticatorTypes: mapping.authenticator_types
    };

    if (mapping.oob_channels) {
      result.oobChannels = mapping.oob_channels;
    }

    if ("phoneNumber" in options && options.phoneNumber !== undefined) {
      result.phoneNumber = options.phoneNumber;
    }

    if ("email" in options && options.email !== undefined) {
      result.email = options.email;
    }

    return result;
  }

  // Passthrough for existing authenticatorTypes format
  return options;
}
