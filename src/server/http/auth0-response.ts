import { Auth0ResponseCookies } from "./auth0-response-cookies.js";

/**
 * An abstract representation of an HTTP response.
 *
 * This base class defines the interface for constructing and modifying HTTP responses
 * without coupling to specific Next.js response types. Implementations provide methods
 * for setting status codes, redirecting, sending JSON/generic content, and managing cookies.
 *
 * The abstraction enables:
 * - Support for multiple response types (NextResponse, NextApiResponse, etc.)
 * - Cleaner authentication logic that returns responses consistently
 * - Easier testing through mock implementations
 *
 * Design pattern: All methods mutate internal state (the `res` property) rather than
 * returning new instances. This allows for method chaining and middleware patterns where
 * the same response object is modified multiple times before being returned.
 *
 * @template TResponse The underlying response type (e.g., NextResponse, NextApiResponse)
 *
 * @example
 * ```typescript
 * // Implementation for NextResponse
 * class Auth0NextResponse extends Auth0Response<NextResponse> {
 *   public redirect(url: string): void {
 *     this.res = NextResponse.redirect(url);
 *   }
 *   // ... other methods
 * }
 *
 * // Usage in authentication logic
 * function handleLogin(res: Auth0Response): void {
 *   res.json({ token: "...", user: {...} });
 *   res.addCacheControlHeadersForSession();
 * }
 * ```
 */
export abstract class Auth0Response<TResponse = any> {
  constructor(public res: TResponse) {}

  /**
   * Retrieves the cookies from the response.
   *
   * @returns An Auth0ResponseCookies object providing a unified interface to cookies.
   */
  abstract getCookies(): Auth0ResponseCookies;

  /**
   * Redirects the response to the specified URL.
   *
   * This method should validate the URL to prevent open redirect vulnerabilities.
   * The implementation must preserve any headers set previously on this response.
   *
   * Security: Ensure URL validation to prevent redirecting users to attacker-controlled
   * sites.
   *
   * @param url - The URL to redirect to. Should be validated before calling this method.
   */
  abstract redirect(url: string): Auth0Response<TResponse>;

  /**
   * Sets the HTTP status code of the response.
   *
   * @param message - The response body as a string or null.
   * @param status - The HTTP status code (e.g., 200, 401, 500).
   *
   * @returns This response object for method chaining.
   */
  abstract status(
    message: string | null,
    status: number
  ): Auth0Response<TResponse>;

  /**
   * Sends a JSON response with the specified body.
   *
   * This method automatically sets the Content-Type header to application/json and
   * serializes the body parameter as JSON.
   *
   * @param body - The response body to be serialized as JSON. May include error details,
   *   user data, or other structured data.
   * @param init - Optional response initialization options (status, headers, etc.).
   *
   * @returns This response object for method chaining.
   */
  abstract json(body: any, init?: ResponseInit): Auth0Response<TResponse>;

  /**
   * Sends a Generic response with the specified body.
   *
   * @param body - The response body to be serialized as JSON. May include error details,
   *   user data, or other structured data.
   * @param init - Optional response initialization options (status, headers, etc.).
   *
   * @returns This response object for method chaining.
   */
  abstract generic(body: any, init?: ResponseInit): Auth0Response<TResponse>;

  /**
   * Adds cache control headers to the response to prevent caching of sensitive data.
   *
   * This should be called for any response containing authenticated user data,
   * access tokens, or other session information that should not be cached.
   *
   * Headers added:
   * - Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0
   * - Pragma: no-cache (HTTP/1.0 compatibility)
   * - Expires: 0 (older browser compatibility)
   *
   * Security: Prevents cached authentication tokens or user information from being
   * served to unauthorized users on shared devices.
   */
  abstract addCacheControlHeadersForSession(): void;

  /**
   * Sets the response to a new response instance, merging headers.
   *
   * This is useful when you have a complete response object from another source
   * and want to preserve headers that were previously set on this response instance.
   * This supports middleware patterns where multiple handlers modify the response.
   *
   * @param res - The new response instance to set.
   *
   * @internal
   */
  abstract setResponse(res: TResponse): void;
}
