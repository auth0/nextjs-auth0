import type { User } from "../types/index.js";

/**
 * Default claims for the ID token.
 */
export const DEFAULT_ID_TOKEN_CLAIMS = [
  "sub",
  "name",
  "nickname",
  "given_name",
  "family_name",
  "picture",
  "email",
  "email_verified",
  "org_id"
];

/**
 * Filters the claims to only include those that are considered default.
 * @param claims The claims to filter.
 * @returns The filtered claims containing only default ID token claims.
 */
export function filterDefaultIdTokenClaims(claims: { [key: string]: any }) {
  return Object.keys(claims).reduce((acc, key) => {
    if (DEFAULT_ID_TOKEN_CLAIMS.includes(key)) {
      acc[key] = claims[key];
    }
    return acc;
  }, {} as User);
}
