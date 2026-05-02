import { SdkError } from "./sdk-error.js";

/**
 * Error codes for mTLS (Mutual TLS) related errors.
 *
 * These error codes categorize failures that can occur during mTLS
 * configuration or operation.
 */
export enum MtlsErrorCode {
  /**
   * `useMtls` was set to `true` but no `customFetch` implementation was provided.
   *
   * mTLS requires a TLS-aware `fetch` replacement (e.g. using Node.js `undici`
   * with a client certificate) because the standard `fetch` global has no API
   * for attaching client certificates. The SDK cannot enforce mTLS without it.
   */
  MTLS_REQUIRES_CUSTOM_FETCH = "mtls_requires_custom_fetch"
}

/**
 * Represents an error that occurred during mTLS (Mutual TLS) configuration.
 *
 * mTLS (RFC 8705) allows a confidential client to authenticate to Auth0 using
 * a TLS client certificate instead of a `client_secret` or a signed JWT
 * assertion. It also enables certificate-bound access tokens, which bind issued
 * tokens cryptographically to the client certificate so that a stolen token
 * cannot be replayed without the matching private key.
 *
 * This error is thrown during `Auth0Client` construction when the mTLS
 * configuration is invalid or incomplete.
 *
 * Common scenarios that trigger `MtlsError`:
 * - `useMtls: true` is set without providing a `customFetch` implementation
 *
 * @example Handling mTLS configuration errors
 * ```typescript
 * import { Auth0Client } from "@auth0/nextjs-auth0/server";
 * import { MtlsError, MtlsErrorCode } from "@auth0/nextjs-auth0/errors";
 *
 * try {
 *   const auth0 = new Auth0Client({
 *     useMtls: true,
 *     // customFetch omitted — will throw
 *   });
 * } catch (error) {
 *   if (error.code === MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH) {
 *     console.error("Provide a TLS-aware customFetch when useMtls is true.");
 *   }
 * }
 * ```
 *
 * @example Providing a valid mTLS configuration (Node.js)
 * ```typescript
 * import { Agent, fetch as undiciFetch } from "undici";
 * import { Auth0Client } from "@auth0/nextjs-auth0/server";
 *
 * const agent = new Agent({
 *   connect: {
 *     key: process.env.AUTH0_MTLS_CLIENT_KEY,
 *     cert: process.env.AUTH0_MTLS_CLIENT_CERT,
 *   },
 * });
 *
 * const auth0 = new Auth0Client({
 *   useMtls: true,
 *   customFetch: (url, init) => undiciFetch(url, { ...init, dispatcher: agent }),
 * });
 * ```
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8705 | RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens}
 */
export class MtlsError extends SdkError {
  /** The specific mTLS error code indicating the type of failure. */
  public code: MtlsErrorCode;

  /**
   * Constructs a new `MtlsError` instance.
   *
   * @param code - The mTLS error code indicating the specific type of failure
   * @param message - A descriptive error message explaining what went wrong
   *
   * @example
   * ```typescript
   * throw new MtlsError(
   *   MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
   *   "useMtls requires a customFetch option with a TLS client certificate."
   * );
   * ```
   */
  constructor(code: MtlsErrorCode, message: string) {
    super(message);
    this.name = "MtlsError";
    this.code = code;
  }
}
