/**
 * The default scopes to request when none are provided.
 */
export const DEFAULT_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access"
].join(" ");

/**
 * Default clock skew in seconds for DPoP proof validation.
 * Used to adjust the assumed current time when validating DPoP proofs.
 */
export const DEFAULT_DPOP_CLOCK_SKEW = 0;

/**
 * Default clock tolerance in seconds for DPoP proof validation.
 * Allows for clock differences between client and server.
 */
export const DEFAULT_DPOP_CLOCK_TOLERANCE = 30;

/**
 * Maximum recommended clock tolerance in seconds for DPoP proof validation.
 * Values exceeding this threshold may weaken DPoP security by allowing
 * replay attacks within a wider time window.
 */
export const MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE = 300;
