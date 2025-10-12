export interface DpopKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

/**
 * Configuration options for DPoP (Demonstrating Proof-of-Possession) timing validation.
 * These options configure how oauth4webapi validates DPoP proof timing.
 */
export interface DpopOptions {
  /**
   * Clock skew adjustment in seconds. Use to adjust the assumed current time.
   * Positive values if local clock is behind, negative if ahead.
   * Maps to oauth4webapi's clockSkew symbol.
   *
   * @default 0
   */
  clockSkew?: number;

  /**
   * Clock tolerance in seconds for DateTime JWT claims validation.
   * Allows for clock differences between client and server.
   * Maps to oauth4webapi's clockTolerance symbol.
   *
   * @default 30
   */
  clockTolerance?: number;

  /**
   * Configuration for DPoP nonce error retry behavior.
   */
  retry?: RetryConfig;
}

/**
 * Configuration options for DPoP nonce error retry behavior.
 * Since DPoP nonce errors are retried only once, this is a simple delay configuration.
 */
export interface RetryConfig {
  /**
   * Delay in milliseconds before retrying on DPoP nonce error.
   * @default 100
   */
  delay?: number;

  /**
   * Whether to add jitter (randomness) to retry delay to prevent thundering herd.
   * When enabled, actual delay will be 50-100% of the configured delay.
   * @default true
   */
  jitter?: boolean;
}
