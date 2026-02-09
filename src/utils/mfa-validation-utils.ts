import type { NextRequest } from "next/server.js";

import { InvalidRequestError } from "../errors/index.js";
import type { VerifyCredentialBody } from "../types/mfa.js";

/**
 * Extracts Bearer token from Authorization header.
 *
 * @param req - NextRequest with Authorization header
 * @returns Bearer token value
 * @throws {InvalidRequestError} If header is missing or invalid format
 */
export function extractBearerToken(req: NextRequest): string {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new InvalidRequestError("Missing or invalid Authorization header");
  }
  return authHeader.substring(7);
}

/**
 * Extracts MFA token from query param or Authorization header.
 * Prioritizes query param (SDK client pattern), falls back to header (API pattern).
 *
 * @param req - NextRequest with mfa_token query param or Authorization header
 * @returns MFA token value
 * @throws {InvalidRequestError} If token is missing from both locations
 */
export function extractMfaToken(req: NextRequest): string {
  // Check query param first (client SDK sends here)
  const url = new URL(req.url);
  const queryToken = url.searchParams.get("mfa_token");
  if (queryToken && queryToken !== "") {
    return queryToken;
  }

  // Fall back to Authorization header (standard OAuth pattern)
  return extractBearerToken(req);
}

/**
 * Type guard to check if value is a non-empty string.
 *
 * @param value - Value to check
 * @returns True if value is a non-empty string
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}

/**
 * Validates that a field is a non-empty string.
 *
 * @param value - Value to validate
 * @param fieldName - Field name for error messages
 * @returns Validated string value
 * @throws {InvalidRequestError} If value is not a non-empty string
 */
export function validateStringFieldAndThrow(
  value: unknown,
  fieldName: string
): string {
  if (!isNonEmptyString(value)) {
    throw new InvalidRequestError(`Missing or invalid ${fieldName}`);
  }
  return value;
}

/**
 * Validates that a field is a non-empty array.
 *
 * @param value - Value to validate
 * @param fieldName - Field name for error messages
 * @returns Validated array
 * @throws {InvalidRequestError} If value is not a non-empty array
 */
export function validateArrayFieldAndThrow(
  value: unknown,
  fieldName: string
): string[] {
  if (!value || !Array.isArray(value) || value.length === 0) {
    throw new InvalidRequestError(`Missing or invalid ${fieldName}`);
  }
  return value;
}

/**
 * Validates that request body contains at least one verification credential.
 * Credentials are: otp, oobCode+bindingCode, or recoveryCode.
 *
 * @param body - Request body to validate
 * @returns Validated credential body
 * @throws {InvalidRequestError} If no valid credential present
 */
export function validateVerificationCredentialAndThrow(
  body: unknown
): VerifyCredentialBody {
  const bodyObj = body as Record<string, unknown>;
  const hasOtp =
    "otp" in bodyObj && typeof bodyObj.otp === "string" && bodyObj.otp !== "";
  const hasOob =
    "oobCode" in bodyObj &&
    typeof bodyObj.oobCode === "string" &&
    bodyObj.oobCode !== "" &&
    "bindingCode" in bodyObj &&
    typeof bodyObj.bindingCode === "string" &&
    bodyObj.bindingCode !== "";
  const hasRecovery =
    "recoveryCode" in bodyObj &&
    typeof bodyObj.recoveryCode === "string" &&
    bodyObj.recoveryCode !== "";

  if (!hasOtp && !hasOob && !hasRecovery) {
    throw new InvalidRequestError(
      "Missing verification credential (otp, oobCode+bindingCode, or recoveryCode required)"
    );
  }

  return bodyObj as VerifyCredentialBody;
}

/**
 * Extracts path parameter from URL pathname.
 *
 * @param pathname - Request URL pathname
 * @param paramName - Parameter name for error messages
 * @returns Extracted parameter value
 * @throws {InvalidRequestError} If parameter is missing
 */
export function extractPathParam(pathname: string, paramName: string): string {
  const value = pathname.split("/").pop();
  if (!value || value === "") {
    throw new InvalidRequestError(`Missing ${paramName} in URL`);
  }
  return value;
}

/**
 * Parses JSON from request body with error handling.
 *
 * @param req - NextRequest to parse
 * @returns Parsed JSON body
 * @throws {InvalidRequestError} If JSON is malformed
 */
export async function parseJsonBody(req: NextRequest): Promise<unknown> {
  try {
    return await req.json();
  } catch (parseError) {
    throw new InvalidRequestError("Invalid JSON in request body");
  }
}
