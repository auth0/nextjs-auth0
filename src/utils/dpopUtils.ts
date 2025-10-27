import {
  createPrivateKey,
  createPublicKey,
  createSign,
  createVerify,
  KeyObject
} from "crypto";
import { generateKeyPair, isDPoPNonceError } from "oauth4webapi";

import { DpopKeyPair, DpopOptions, RetryConfig } from "../types/dpop.js";
import {
  DEFAULT_DPOP_CLOCK_SKEW,
  DEFAULT_DPOP_CLOCK_TOLERANCE,
  DEFAULT_RETRY_DELAY,
  DEFAULT_RETRY_JITTER,
  MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE
} from "./constants.js";

/**
 * Detects if the current environment is Edge Runtime.
 * Edge Runtime environments have limited Node.js API support.
 */
function isEdgeRuntime(): boolean {
  return typeof (globalThis as any).EdgeRuntime === "string";
}

/**
 * Generates a new ES256 key pair for DPoP (Demonstrating Proof-of-Possession) operations.
 *
 * This function creates a cryptographically secure ES256 key pair suitable for DPoP proof
 * generation. The generated keys use the P-256 elliptic curve with SHA-256 hashing,
 * which is the required algorithm for DPoP as specified in RFC 9449.
 *
 * @returns Promise that resolves to a DpopKeyPair containing the private and public keys
 *
 * @example
 * ```typescript
 * import { generateDpopKeyPair } from "@auth0/nextjs-auth0/server";
 *
 * const keyPair = await generateDpopKeyPair();
 *
 * const auth0 = new Auth0Client({
 *   useDPoP: true,
 *   dpopKeyPair: keyPair
 * });
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9449 | RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)}
 */
export async function generateDpopKeyPair(): Promise<DpopKeyPair> {
  return await generateKeyPair("ES256");
}

/**
 * Executes a function with retry logic for DPoP nonce errors.
 *
 * DPoP nonce errors occur when the authorization server requires a fresh nonce
 * for replay attack prevention. This function implements a single retry pattern
 * with configurable delay and jitter to handle these errors gracefully.
 *
 * The retry mechanism:
 * 1. Executes the provided function
 * 2. If a DPoP nonce error occurs, waits for the configured delay
 * 3. Retries the function once with the cached nonce from the error response
 * 4. If the retry fails or any other error occurs, re-throws the error
 *
 * @template T - The return type of the function being executed
 * @param fn - The async function to execute with retry logic
 * @param retryConfig - Configuration for retry behavior (delay and jitter)
 * @returns The result of the function execution
 * @throws The original error if it's not a DPoP nonce error or if retry fails
 *
 * @example
 * ```typescript
 * import { withDPoPNonceRetry } from "@auth0/nextjs-auth0/server";
 *
 * const result = await withDPoPNonceRetry(async () => {
 *   return await protectedResourceRequest(
 *     accessToken,
 *     "GET",
 *     new URL("https://api.example.com/data"),
 *     headers,
 *     null,
 *     { DPoP: dpopHandle }
 *   );
 * });
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9449#section-7.1 | RFC 9449 Section 7.1: DPoP Nonce}
 */
export async function withDPoPNonceRetry<T>(
  fn: () => Promise<T>,
  retryConfig?: RetryConfig
): Promise<T> {
  try {
    return await fn();
  } catch (error: any) {
    if (isDPoPNonceError(error)) {
      // Use provided config or defaults
      const delay = retryConfig?.delay ?? 100;
      const jitter = retryConfig?.jitter ?? true;

      let actualDelay = delay;

      // Apply jitter if enabled (50-100% of original delay to prevent thundering herd)
      if (jitter) {
        actualDelay = delay * (0.5 + Math.random() * 0.5);
      }

      // Delay before retry to avoid rapid successive requests
      await new Promise((resolve) => setTimeout(resolve, actualDelay));

      // The RS-signalled nonce is now cached, retrying
      return await fn();
    }
    throw error;
  }
}

/**
 * Validates that a private and public key form a compatible key pair
 * by attempting to sign and verify a test message.
 *
 * This function ensures that the provided private and public keys are mathematically
 * compatible by performing a sign-and-verify operation with test data. This validation
 * helps catch mismatched key pairs, corrupted keys, or incorrect key formats early.
 *
 * @param privateKey - The private key as a Node.js KeyObject
 * @param publicKey - The public key as a Node.js KeyObject
 * @returns true if keys are compatible, false otherwise
 *
 * @example
 * ```typescript
 * import { createPrivateKey, createPublicKey } from "crypto";
 * import { validateKeyPairCompatibility } from "@auth0/nextjs-auth0/server";
 *
 * const privateKey = createPrivateKey(privateKeyPem);
 * const publicKey = createPublicKey(publicKeyPem);
 *
 * if (validateKeyPairCompatibility(privateKey, publicKey)) {
 *   console.log("Keys are compatible");
 * } else {
 *   console.log("Keys are not compatible");
 * }
 * ```
 */
export function validateKeyPairCompatibility(
  privateKey: KeyObject,
  publicKey: KeyObject
): boolean {
  // Skip key pair validation in Edge Runtime environments
  // Edge Runtime doesn't have access to Node.js crypto APIs needed for validation
  if (isEdgeRuntime()) {
    return true;
  }

  try {
    // Create test data
    const testData = "test-data-for-key-pair-validation";

    // Sign with private key
    const sign = createSign("sha256");
    sign.update(testData);
    const signature = sign.sign(privateKey);

    // Verify with public key
    const verify = createVerify("sha256");
    verify.update(testData);
    const isValid = verify.verify(publicKey, signature);

    if (!isValid) {
      console.warn(
        "WARNING: Private and public keys do not form a valid key pair - signature verification failed. " +
          "Please ensure the keys are properly paired and in the correct format. " +
          "DPoP will be disabled and bearer authentication will be used instead."
      );
      return false;
    }

    return true;
  } catch (error) {
    console.warn(
      "WARNING: Failed to validate key pair compatibility. " +
        "This may indicate invalid key format, mismatched algorithms, or corrupted key data. " +
        "DPoP will be disabled and bearer authentication will be used instead. " +
        `Error: ${error instanceof Error ? error.message : String(error)}`
    );
    return false;
  }
}

/**
 * Configuration options for DPoP validation.
 * This interface mirrors the relevant options from Auth0ClientOptions.
 */
export interface DpopConfigurationOptions {
  useDPoP?: boolean;
  dpopKeyPair?: DpopKeyPair;
  dpopOptions?: DpopOptions;
}

/**
 * Validates DPoP configuration and returns keypair and options if available.
 * Attempts to load from environment variables if not provided in options.
 *
 * **Validation Behavior:**
 * - **Success**: Returns both `dpopKeyPair` and `dpopOptions`
 * - **Validation Failure**: Returns `{ dpopKeyPair: undefined, dpopOptions: undefined }`
 *
 * When DPoP cannot be properly configured, the system falls back to bearer authentication.
 *
 * **Performance Characteristics - Synchronous Key Loading:**
 *
 * Key loading and validation are performed synchronously during Auth0Client constructor execution.
 *
 * **Optimization Strategies:**
 * - **Recommended**: Pre-generate keys and pass via `dpopKeyPair` option to avoid env var parsing
 * - **Module-Level**: Instantiate Auth0Client at module level (lib/auth0.ts) for one-time cost
 * - **High-Throughput**: Consider pre-loading keys outside constructor for serverless environments
 *
 * @example Performance-optimized initialization
 * ```typescript
 * // Optimal: Pre-generated keys (no env var parsing)
 * import { generateKeyPair } from "oauth4webapi";
 * const dpopKeyPair = await generateKeyPair("ES256");
 * export const auth0 = new Auth0Client({ useDPoP: true, dpopKeyPair });
 * ```
 *
 * **Security-sensitive configuration:**
 * - `clockSkew`: Difference between client and server clocks (default: {@link DEFAULT_DPOP_CLOCK_SKEW})
 * - `clockTolerance`: Acceptable time drift for DPoP proof validation (default: {@link DEFAULT_DPOP_CLOCK_TOLERANCE}, max recommended: {@link MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE})
 *
 * Values exceeding {@link MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE} will trigger a warning but are not enforced.
 * Excessively large clock tolerance values may weaken DPoP security by allowing replay attacks within a
 * wider time window. Prefer synchronizing server clocks using NTP instead of increasing tolerance.
 *
 * @param options The configuration options containing DPoP settings
 * @returns Object containing DpopKeyPair and DpopOptions if validation succeeds, or both undefined if validation fails
 */
export function validateDpopConfiguration(options: DpopConfigurationOptions): {
  dpopKeyPair?: DpopKeyPair;
  dpopOptions?: DpopOptions;
} {
  const useDPoP = options.useDPoP || false;

  // If DPoP is not enabled, return early with undefined values
  if (!useDPoP) {
    return { dpopKeyPair: undefined, dpopOptions: undefined };
  }

  // Build DPoP options with defaults from environment variables or provided options
  const clockTolerance =
    options.dpopOptions?.clockTolerance ??
    (process.env.AUTH0_DPOP_CLOCK_TOLERANCE
      ? parseInt(process.env.AUTH0_DPOP_CLOCK_TOLERANCE, 10)
      : DEFAULT_DPOP_CLOCK_TOLERANCE);

  // Warn if clock tolerance exceeds recommended maximum (but don't enforce)
  if (clockTolerance > MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE) {
    const productionMaxTolerance = process.env
      .AUTH0_DPOP_CLOCK_TOLERANCE_MAX_PROD
      ? parseInt(process.env.AUTH0_DPOP_CLOCK_TOLERANCE_MAX_PROD, 10)
      : MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE;

    if (
      process.env.NODE_ENV === "production" &&
      clockTolerance > productionMaxTolerance
    ) {
      throw new Error(
        `clockTolerance of ${clockTolerance}s exceeds maximum allowed ${productionMaxTolerance}s in production. ` +
          "This could significantly weaken DPoP replay attack protection. " +
          "Set AUTH0_DPOP_CLOCK_TOLERANCE_MAX_PROD environment variable to override this limit in production."
      );
    }

    console.warn(
      `WARNING: clockTolerance of ${clockTolerance}s exceeds recommended maximum of ${MAX_RECOMMENDED_DPOP_CLOCK_TOLERANCE}s. ` +
        "This may weaken DPoP security by allowing replay attacks within a wider time window. " +
        "Consider synchronizing server clocks using NTP instead of increasing tolerance."
    );
  }

  const dpopOptions: DpopOptions = {
    clockSkew:
      options.dpopOptions?.clockSkew ??
      (process.env.AUTH0_DPOP_CLOCK_SKEW
        ? parseInt(process.env.AUTH0_DPOP_CLOCK_SKEW, 10)
        : DEFAULT_DPOP_CLOCK_SKEW),
    clockTolerance,
    retry: {
      delay:
        options.dpopOptions?.retry?.delay ??
        (process.env.AUTH0_RETRY_DELAY
          ? parseInt(process.env.AUTH0_RETRY_DELAY, 10)
          : DEFAULT_RETRY_DELAY),
      jitter:
        options.dpopOptions?.retry?.jitter ??
        (process.env.AUTH0_RETRY_JITTER
          ? process.env.AUTH0_RETRY_JITTER === "true"
          : DEFAULT_RETRY_JITTER)
    }
  };

  // Validate retry configuration
  if (
    dpopOptions.retry &&
    typeof dpopOptions.retry.delay === "number" &&
    dpopOptions.retry.delay < 0
  ) {
    throw new Error("Retry delay must be non-negative");
  }

  // If we already have a keypair, return it with options
  if (options.dpopKeyPair) {
    return {
      dpopKeyPair: options.dpopKeyPair,
      dpopOptions
    };
  }

  // If DPoP is enabled but no keypair provided, check if environment variables exist
  if (useDPoP) {
    const privateKeyPem = process.env.AUTH0_DPOP_PRIVATE_KEY;
    const publicKeyPem = process.env.AUTH0_DPOP_PUBLIC_KEY;

    // In Edge Runtime, we can't use Node.js crypto APIs to load keys from environment variables
    if (isEdgeRuntime() && (privateKeyPem || publicKeyPem)) {
      console.warn(
        "WARNING: Running in Edge Runtime environment. DPoP keypair loading from environment variables " +
          "is not supported due to limited Node.js crypto API access. DPoP has been disabled. " +
          "To use DPoP in Edge Runtime, provide a pre-generated keypair via the dpopKeyPair option."
      );
      return { dpopKeyPair: undefined, dpopOptions: undefined };
    }

    if (privateKeyPem && publicKeyPem) {
      try {
        // Note: Key loading is performed synchronously during initialization.
        // Ensure keys are pre-loaded or cached to avoid blocking the event loop.
        const privateKeyNodeJS = createPrivateKey(privateKeyPem);
        const publicKeyNodeJS = createPublicKey(publicKeyPem);

        // Validate algorithm - DPoP requires ES256 (ECDSA using P-256 and SHA-256)
        if (privateKeyNodeJS.asymmetricKeyType !== "ec") {
          throw new Error(
            `DPoP private key must be an Elliptic Curve key for ES256 algorithm, got: ${privateKeyNodeJS.asymmetricKeyType}`
          );
        }

        if (publicKeyNodeJS.asymmetricKeyType !== "ec") {
          throw new Error(
            `DPoP public key must be an Elliptic Curve key for ES256 algorithm, got: ${publicKeyNodeJS.asymmetricKeyType}`
          );
        }

        const privateKeyDetails = privateKeyNodeJS.asymmetricKeyDetails;
        const publicKeyDetails = publicKeyNodeJS.asymmetricKeyDetails;

        // Validate P-256 curve requirement for ES256 algorithm
        if (privateKeyDetails?.namedCurve !== "prime256v1") {
          throw new Error(
            `DPoP private key must use P-256 curve (prime256v1) for ES256 algorithm, got: ${privateKeyDetails?.namedCurve}`
          );
        }

        if (publicKeyDetails?.namedCurve !== "prime256v1") {
          throw new Error(
            `DPoP public key must use P-256 curve (prime256v1) for ES256 algorithm, got: ${publicKeyDetails?.namedCurve}`
          );
        }

        // Validate key pair compatibility
        const isKeyPairValid = validateKeyPairCompatibility(
          privateKeyNodeJS,
          publicKeyNodeJS
        );

        if (!isKeyPairValid) {
          // Key pair validation failed, completely disable DPoP to ensure consistent state
          // When validation fails, we should not use DPoP at all and fallback to bearer auth
          console.warn(
            "WARNING: DPoP key pair validation failed. DPoP has been completely disabled. " +
              "Falling back to bearer authentication. Please verify your key pair configuration."
          );
          return { dpopKeyPair: undefined, dpopOptions: undefined };
        }

        // Convert NodeJS KeyObjects to CryptoKeys synchronously
        const privateKey = privateKeyNodeJS.toCryptoKey("ES256", false, [
          "sign"
        ]);
        const publicKey = publicKeyNodeJS.toCryptoKey("ES256", false, [
          "verify"
        ]);

        return {
          dpopKeyPair: { privateKey, publicKey },
          dpopOptions
        };
      } catch (error) {
        console.warn(
          "WARNING: Failed to load DPoP keypair from environment variables. " +
            "Please ensure AUTH0_DPOP_PUBLIC_KEY and AUTH0_DPOP_PRIVATE_KEY contain valid ES256 keys in PEM format. " +
            `Error: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }

    if (!privateKeyPem || !publicKeyPem) {
      // Issue warning if no keypair is available
      console.warn(
        "WARNING: useDPoP is set to true but dpopKeyPair is not provided. " +
          "DPoP will not be used and protected requests will use bearer authentication instead. " +
          "To enable DPoP, provide a dpopKeyPair in the Auth0Client options or set " +
          "AUTH0_DPOP_PUBLIC_KEY and AUTH0_DPOP_PRIVATE_KEY environment variables."
      );
    }
  }

  // No DPoP keypair available, but DPoP is enabled, return options without keypair
  return { dpopKeyPair: undefined, dpopOptions };
}
