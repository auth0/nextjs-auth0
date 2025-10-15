/**
 * The default scopes to request when none are provided.
 * These scopes provide basic user information and authentication capabilities.
 */
export const DEFAULT_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access"
].join(" ");

/**
 * Default clock skew in seconds for DPoP proof validation.
 *
 * Clock skew adjusts the assumed current time when validating DPoP proofs.
 * Use positive values when the local clock is behind the server,
 * negative values when the local clock is ahead.
 *
 * @default 0 - No clock adjustment needed
 */
export const DEFAULT_DPOP_CLOCK_SKEW = 0;

/**
 * Default clock tolerance in seconds for DPoP proof validation.
 *
 * Allows for reasonable clock differences between client and server during
 * DPoP proof validation. Higher values are more permissive but may weaken
 * security by allowing replay attacks within a wider time window.
 *
 * @default 30 - Allows 30 seconds clock difference
 */
export const DEFAULT_DPOP_CLOCK_TOLERANCE = 30;

/**
 * Maximum recommended clock tolerance in seconds for DPoP proof validation.
 *
 * Values exceeding this threshold may significantly weaken DPoP security
 * by allowing replay attacks within a wider time window. Production
 * applications should use NTP for clock synchronization instead of
 * increasing tolerance beyond this limit.
 *
 * @default 300 - 5 minutes maximum recommended tolerance
 */
export const MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE = 300;

/**
 * Default retry delay in milliseconds for DPoP nonce errors.
 *
 * When a DPoP nonce error occurs, the SDK waits this duration before
 * retrying the request with the new nonce provided by the server.
 * This helps prevent overwhelming the server with rapid retry attempts.
 *
 * @default 100 - 100 milliseconds delay
 */
export const DEFAULT_RETRY_DELAY = 100;

/**
 * Default jitter setting for retry delay.
 *
 * When enabled, adds randomness to the retry delay (50-100% of configured delay)
 * to prevent thundering herd effects when multiple clients encounter
 * nonce errors simultaneously.
 *
 * @default true - Jitter enabled for better load distribution
 */
export const DEFAULT_RETRY_JITTER = true;
