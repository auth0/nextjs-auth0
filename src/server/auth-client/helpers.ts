import { NextResponse } from "next/server.js";
import * as jose from "jose";

import {
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode,
  DPoPErrorCode
} from "../../errors/index.js";
import { normalizeDomain } from "../../utils/normalize.js";

export const encodeBase64 = (input: string) => {
  const unencoded = new TextEncoder().encode(input);
  const CHUNK_SIZE = 0x8000;
  const arr = [];
  for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
    arr.push(
      // @ts-expect-error Argument of type 'Uint8Array' is not assignable to parameter of type 'number[]'.
      String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE))
    );
  }
  return btoa(arr.join(""));
};

/**
 * Identifies a DPoP failure by its `code` rather than an `instanceof` check.
 * `instanceof` is unreliable across module/realm boundaries (duplicate copies
 * of the error class), so we match on the well-known DPoP error codes instead.
 *
 * @internal
 */
export function isDPoPError(
  e: unknown
): e is { code: DPoPErrorCode; message: string } {
  return (
    typeof e === "object" &&
    e !== null &&
    "code" in e &&
    "message" in e &&
    typeof (e as { message: unknown }).message === "string" &&
    Object.values(DPoPErrorCode).includes((e as { code: DPoPErrorCode }).code)
  );
}

/**
 * Creates a NextResponse for BCLO error cases.
 * Centralizes the response format (text/plain content type) for all BCLO error branches.
 *
 * @internal
 */
export function bcloErrorResponse(
  message: string,
  status: number
): NextResponse {
  return new NextResponse(message, {
    status,
    headers: { "Content-Type": "text/plain" }
  });
}

/**
 * Extracts and normalizes the issuer domain from an unverified logout token.
 *
 * Returns `[null, { domain, issuer }]` on success, or `[Error, null]` if the token
 * cannot be decoded, has no iss claim, or the issuer domain fails normalization
 * (e.g., IP address, localhost).
 *
 * SECURITY: This function decodes the JWT without verification. The unverified
 * `iss` claim is used ONLY for comparison against an independently-resolved domain
 * (resolver mode) or the configured static domain (static mode). It does NOT
 * determine which cryptographic key is used for verification — the JWKS source is
 * determined by the resolver/configuration, not by the token itself. This prevents
 * issuer-substitution attacks where an attacker supplies a token with a crafted
 * `iss` and has it verified against their own JWKS.
 *
 * @internal
 */
export function extractIssuerDomainFromToken(
  logoutToken: string
): [Error, null] | [null, { domain: string; issuer: string }] {
  try {
    const { iss } = jose.decodeJwt(logoutToken);
    if (typeof iss !== "string" || !iss) {
      return [
        new Error("Missing or invalid 'iss' claim in logout token."),
        null
      ];
    }
    return [null, normalizeDomain(iss)];
  } catch (err) {
    return [err instanceof Error ? err : new Error(String(err)), null];
  }
}

export function warnIfNotCertificateBound(accessToken: string): void {
  try {
    const payload = jose.decodeJwt(accessToken);
    const cnf = payload["cnf"] as Record<string, unknown> | undefined;
    if (!cnf?.["x5t#S256"]) {
      console.warn(
        "[nextjs-auth0] useMtls is enabled but the issued access token does not contain " +
          "a cnf.x5t#S256 claim. The token is not certificate-bound. " +
          "Verify that mTLS is correctly configured on your Auth0 tenant and that " +
          "token requests are routed through your mTLS custom domain."
      );
    }
  } catch {
    // decodeJwt only fails for opaque tokens — skip the check silently
  }
}

/**
 * Validates subject_token_type: 10-100 chars, valid URI (URL or URN).
 * The 10-100 length constraint matches the Auth0 CTE Profile Management API requirement
 * for subject_token_type, which is used as a routing key to select a profile.
 */
export function validateSubjectTokenType(
  type: string
): CustomTokenExchangeError | null {
  if (type.length < 10) {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE,
      `Invalid subject_token_type: must be at least 10 characters. Received ${type.length} characters.`
    );
  }
  if (type.length > 100) {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE,
      `Invalid subject_token_type: must be at most 100 characters. Received ${type.length} characters.`
    );
  }
  return validateTokenTypeUri(type, "subject_token_type");
}

/**
 * Validates actor_token_type: valid URI (URL or URN).
 * No length constraint — actor_token_type is not registered in a CTE profile
 * and RFC 8693 §3 imposes no length limit on token type URIs.
 */
export function validateActorTokenType(
  type: string
): CustomTokenExchangeError | null {
  return validateTokenTypeUri(type, "actor_token_type");
}

export function validateTokenTypeUri(
  type: string,
  field: "subject_token_type" | "actor_token_type"
): CustomTokenExchangeError | null {
  let isValidUrl = false;
  try {
    new URL(type);
    isValidUrl = true;
  } catch {
    // Not a valid URL, check URN format next
  }

  // URN format: urn:<nid>:<nss> where nid is alphanumeric (can contain hyphens)
  const isValidUrn =
    /^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$/i.test(type);

  if (!isValidUrl && !isValidUrn) {
    const code =
      field === "actor_token_type"
        ? CustomTokenExchangeErrorCode.INVALID_ACTOR_TOKEN_TYPE
        : CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE;
    return new CustomTokenExchangeError(
      code,
      `Invalid ${field}: must be a valid URI (URL or URN format). Received: "${type}"`
    );
  }

  return null;
}
