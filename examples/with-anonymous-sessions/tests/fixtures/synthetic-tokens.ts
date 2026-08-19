/**
 * SYNTHETIC test fixtures modeling WIRE-CONTRACT-LIVE.md shapes.
 * NO real tokens/secrets — all values are FAKE for deterministic MSW replay.
 */

/**
 * Fake JWT-shaped access token (base64url-encoded header.payload.signature)
 * Payload decodes to: {sub:"anon@00000000-0000-0000-0000-000000000000", aud:"https://api.customers", scope:"read:customers"}
 */
export const SYNTHETIC_ACCESS_TOKEN =
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbm9uQDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsImF1ZCI6Imh0dHBzOi8vYXBpLmN1c3RvbWVycyIsImlzcyI6Imh0dHBzOi8vZGV2LW96dS5leGFtcGxlLmNvbS8iLCJzY29wZSI6InJlYWQ6Y3VzdG9tZXJzIiwiaWF0IjoxNzI1MzAwMDAwLCJleHAiOjE3MjUzMDcyMDB9.FAKE_SIGNATURE";

/**
 * Renewed access token (different signature, same sub/aud, new exp)
 */
export const SYNTHETIC_ACCESS_TOKEN_RENEWED =
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbm9uQDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsImF1ZCI6Imh0dHBzOi8vYXBpLmN1c3RvbWVycyIsImlzcyI6Imh0dHBzOi8vZGV2LW96dS5leGFtcGxlLmNvbS8iLCJzY29wZSI6InJlYWQ6Y3VzdG9tZXJzIiwiaWF0IjoxNzI1MzA3MjAwLCJleHAiOjE3MjUzMTQ0MDB9.RENEWED_FAKE_SIGNATURE";

/**
 * Fake JWE-shaped session_token (opaque handle, NOT a real JWT)
 */
export const SYNTHETIC_SESSION_TOKEN =
  "ANONYMOUS_SESSION_synthetic_fake_jwe_handle_12345";

/**
 * Fake client credentials (NOT real)
 */
export const SYNTHETIC_CLIENT_ID = "SYNTHETIC_CLIENT_ID_for_test";
export const SYNTHETIC_CLIENT_SECRET =
  "SYNTHETIC_CLIENT_SECRET_for_test_do_not_commit_real";
export const SYNTHETIC_DOMAIN = "https://dev-ozu.example.com";
export const SYNTHETIC_AUDIENCE = "https://api.customers";

/**
 * Wire-shape fixtures per WIRE-CONTRACT-LIVE.md
 */

/** CREATE response (200 OK) */
export const WIRE_CREATE_RESPONSE = {
  token_type: "Bearer" as const,
  session_expires_in: 2592000, // 30 days
  session_token: SYNTHETIC_SESSION_TOKEN,
  access_token: SYNTHETIC_ACCESS_TOKEN,
  expires_in: 7200 // 2 hours
};

/** CREATE with metadata response (200 OK) */
export const WIRE_CREATE_WITH_METADATA_RESPONSE = {
  token_type: "Bearer" as const,
  session_expires_in: 2592000,
  session_token: SYNTHETIC_SESSION_TOKEN,
  access_token: SYNTHETIC_ACCESS_TOKEN,
  expires_in: 7200
};

/** RENEW response (200 OK, NO session_token reissue) */
export const WIRE_RENEW_RESPONSE = {
  token_type: "Bearer" as const,
  access_token: SYNTHETIC_ACCESS_TOKEN_RENEWED,
  expires_in: 7200
};

/** RENEW + metadata error (400 Bad Request) */
export const WIRE_RENEW_WITH_METADATA_ERROR = {
  error: "invalid_request",
  error_description: "metadata cannot be provided when session_token is present"
};

/** LOGOUT error with session_token in body (400 Bad Request) */
export const WIRE_LOGOUT_WITH_SESSION_TOKEN_ERROR = {
  error: "invalid_request",
  error_description: "The request is invalid"
};

/** Metadata example */
export const SYNTHETIC_METADATA = {
  cart_id: "cart_123",
  items: 3
};
