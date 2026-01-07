import { ReadonlyRequestCookies, RequestCookies } from "../cookies.js";

/**
 * A wrapper around RequestCookies to provide a unified interface for reading and
 * modifying cookies in request contexts.
 *
 * This class abstracts the @edge-runtime/cookies library and provides a simple
 * interface for authentication logic to interact with request cookies. It supports
 * both readonly contexts (like middleware) and writable contexts.
 *
 * Cookie values are parsed from the Cookie header and may be user-controlled.
 * All cookie values should be treated as untrusted and validated before use in
 * security decisions.
 *
 * Implementation notes:
 * - Cookies are HTTP-only and cannot be modified by JavaScript on the client-side
 * - Cookie values may contain special characters and should be URL-encoded
 * - Large cookies are chunked (e.g., __session__0, __session__1) by the abstraction layer
 * - Changes made via set() or delete() are propagated to the response
 *
 * Security considerations:
 * - Never trust cookie values for authentication (validate signatures/tokens)
 * - Use secure, HttpOnly, and SameSite flags when setting cookies (handled by abstraction)
 * - Be aware of cookie size limits (typically 4KB per cookie)
 * - Consider cookie expiration times to limit exposure of compromised cookies
 *
 * @example
 * ```typescript
 * const cookies = auth0Req.getCookies();
 *
 * // Get a single cookie
 * const sessionCookie = cookies.get("auth0-session");
 * if (sessionCookie) {
 *   const sessionValue = sessionCookie.value;
 * }
 *
 * // Get all cookies
 * const allCookies = cookies.getAll();
 *
 * // Check if a cookie exists
 * if (cookies.has("auth0-session")) {
 *   // Cookie exists
 * }
 *
 * // Modify cookies (for request context, enables read-after-write)
 * cookies.set("new-cookie", "value");
 * cookies.delete("old-cookie");
 * ```
 */
export class Auth0RequestCookies {
  constructor(
    private cookies: ReadonlyRequestCookies | RequestCookies
  ) {}

  /**
   * Retrieves a cookie by name.
   *
   * Returns undefined if the cookie does not exist.
   *
   * @param name The name of the cookie to retrieve.
   * @returns An object containing the name and value of the cookie, or undefined if not found.
   */
  get(name: string): { name: string; value: string } | undefined {
    const value = this.cookies.get(name);
    if (value === undefined) {
      return undefined;
    }
    return { name, value: value.value };
  }

  /**
   * Retrieves all cookies.
   *
   * @returns An array of objects containing the names and values of all cookies.
   */
  getAll(): Array<{ name: string; value: string }> {
    return this.cookies.getAll().map((cookie) => ({
      name: cookie.name,
      value: cookie.value
    }));
  }

  /**
   * Checks if a cookie exists by name.
   *
   * @param name The name of the cookie to check.
   * @returns True if the cookie exists, false otherwise.
   */
  has(name: string): boolean {
    return this.cookies.has(name);
  }

  /**
   * Sets a cookie value.
   *
   * This method enables read-after-write in middleware contexts, allowing subsequent
   * requests to see the cookie value that was just set. The actual cookie is set on
   * the response via the response cookies abstraction.
   *
   * @param name The name of the cookie to set.
   * @param value The value of the cookie to set. Should be URL-encoded if needed.
   */
  set(name: string, value: string): void {
    this.cookies.set(name, value);
  }

  /**
   * Deletes a cookie by name.
   *
   * @param name The name of the cookie to delete.
   */
  delete(name: string): void {
    this.cookies.delete(name);
  }
}
