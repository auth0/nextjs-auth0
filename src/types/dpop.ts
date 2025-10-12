/**
 * ES256 key pair used for DPoP (Demonstrating Proof-of-Possession) operations.
 *
 * DPoP requires an ES256 (ECDSA using P-256 and SHA-256) key pair to generate
 * cryptographic proofs that bind access tokens to the client's private key.
 * This prevents token theft and replay attacks.
 *
 * @example Generating a key pair
 * ```typescript
 * import { generateKeyPair } from "oauth4webapi";
 *
 * const dpopKeyPair = await generateKeyPair("ES256");
 *
 * const auth0 = new Auth0Client({
 *   useDpop: true,
 *   dpopKeyPair
 * });
 * ```
 *
 * @example Loading from environment variables
 * ```typescript
 * // Set in .env.local:
 * // AUTH0_DPOP_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----..."
 * // AUTH0_DPOP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."
 *
 * const auth0 = new Auth0Client({
 *   useDpop: true
 *   // Keys will be loaded automatically from environment
 * });
 * ```
 */
export interface DpopKeyPair {
  /** ES256 private key used to sign DPoP proofs */
  privateKey: CryptoKey;
  /** ES256 public key included in DPoP proofs for verification */
  publicKey: CryptoKey;
}

/**
 * Configuration options for DPoP (Demonstrating Proof-of-Possession) timing validation.
 *
 * These options configure how the SDK validates DPoP proof timing using oauth4webapi.
 * Proper timing configuration is crucial for security while allowing for reasonable
 * clock differences between client and server.
 *
 * @example Basic configuration
 * ```typescript
 * const auth0 = new Auth0Client({
 *   useDpop: true,
 *   dpopOptions: {
 *     clockTolerance: 60, // Allow 60 seconds clock difference
 *     clockSkew: 0,       // No clock skew adjustment
 *     retry: {
 *       delay: 200,       // 200ms delay before retry
 *       jitter: true      // Add randomness to prevent thundering herd
 *     }
 *   }
 * });
 * ```
 *
 * @example Environment variable configuration
 * ```bash
 * # In .env.local
 * AUTH0_DPOP_CLOCK_SKEW=0
 * AUTH0_DPOP_CLOCK_TOLERANCE=30
 * AUTH0_RETRY_DELAY=100
 * AUTH0_RETRY_JITTER=true
 * ```
 */
export interface DpopOptions {
  /**
   * Clock skew adjustment in seconds. Use to adjust the assumed current time.
   *
   * - Positive values: Use when local clock is behind the server
   * - Negative values: Use when local clock is ahead of the server
   * - Zero (default): No adjustment needed
   *
   * Maps to oauth4webapi's clockSkew symbol.
   *
   * @default 0
   * @example
   * ```typescript
   * // If server time is 30 seconds ahead of client
   * dpopOptions: {
   *   clockSkew: 30  // Adjust client time forward by 30 seconds
   * }
   * ```
   */
  clockSkew?: number;

  /**
   * Clock tolerance in seconds for DateTime JWT claims validation.
   *
   * Allows for clock differences between client and server during DPoP proof validation.
   * Higher values are more permissive but may weaken security by allowing replay attacks
   * within a wider time window.
   *
   * Maps to oauth4webapi's clockTolerance symbol.
   *
   * @default 30
   * @example
   * ```typescript
   * dpopOptions: {
   *   clockTolerance: 60  // Allow 60 seconds difference
   * }
   * ```
   *
   * @warning Values above 300 seconds may significantly weaken DPoP security
   */
  clockTolerance?: number;

  /**
   * Configuration for DPoP nonce error retry behavior.
   *
   * When a server responds with a DPoP nonce error, the SDK will retry the request
   * once with the new nonce. This configuration controls the retry timing.
   */
  retry?: RetryConfig;
}

/**
 * Configuration options for DPoP nonce error retry behavior.
 *
 * Since DPoP nonce errors are retried only once (to prevent infinite loops),
 * this configuration focuses on timing the single retry attempt for optimal
 * performance and server load distribution.
 *
 * @example Basic retry configuration
 * ```typescript
 * retry: {
 *   delay: 100,    // Wait 100ms before retry
 *   jitter: true   // Add randomness (50-100ms actual delay)
 * }
 * ```
 *
 * @example Disable jitter for predictable timing
 * ```typescript
 * retry: {
 *   delay: 200,    // Exactly 200ms delay
 *   jitter: false  // No randomness
 * }
 * ```
 */
export interface RetryConfig {
  /**
   * Delay in milliseconds before retrying on DPoP nonce error.
   *
   * A small delay helps prevent overwhelming the authorization server
   * with rapid retry attempts while keeping response times reasonable.
   *
   * @default 100
   * @example
   * ```typescript
   * retry: {
   *   delay: 250  // Wait 250ms before retry
   * }
   * ```
   */
  delay?: number;

  /**
   * Whether to add jitter (randomness) to retry delay to prevent thundering herd.
   *
   * When enabled, the actual delay will be 50-100% of the configured delay.
   * This helps distribute retry attempts over time when multiple clients
   * encounter nonce errors simultaneously.
   *
   * @default true
   * @example
   * ```typescript
   * retry: {
   *   delay: 100,
   *   jitter: true   // Actual delay: 50-100ms
   * }
   *
   * retry: {
   *   delay: 100,
   *   jitter: false  // Actual delay: exactly 100ms
   * }
   * ```
   */
  jitter?: boolean;
}
