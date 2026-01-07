import { ResponseCookies } from "../cookies.js";

/**
 * A wrapper around ResponseCookies to provide a unified interface for setting
 * response cookies across different Next.js contexts.
 *
 * @example
 * ```typescript
 * const cookies = auth0Res.getCookies();
 *
 * // Set a cookie with options
 * cookies.set("session", "token123", {
 *   httpOnly: true,
 *   secure: true,
 *   sameSite: "lax",
 *   maxAge: 86400, // 1 day
 *   path: "/"
 * });
 *
 * // Delete a cookie
 * cookies.delete("session");
 *
 * // Check if a cookie exists
 * if (cookies.has("session")) {
 *   const cookie = cookies.get("session");
 * }
 * ```
 */
export class Auth0ResponseCookies {
  constructor(
    private responseCookies: ResponseCookies
  ) {}

  /**
   * Retrieves a cookie by name.
   * 
   * @param name The name of the cookie to retrieve.
   * @returns The cookie object if found, undefined otherwise.
   */
  get(name: string) {
    return this.responseCookies.get(name);
  }

  /**
   * Retrieves all cookies.
   * 
   * @returns An array of all cookies with their attributes.
   */
  getAll(...args: Parameters<ResponseCookies["getAll"]>) {
    return this.responseCookies.getAll(...args);
  }

  /**
   * Checks if a cookie exists by name.

   * @param name The name of the cookie to check.
   * @returns True if the cookie exists, false otherwise.
   */
  has(name: string): boolean {
    return this.responseCookies.has(name);
  }

  /**
   * Sets a cookie with the specified name, value, and options.
   *
   * This method supports setting cookies with full control over attributes like
   * HttpOnly, Secure, SameSite, maxAge, path, and domain. Large cookie values
   * are automatically chunked into multiple cookies if needed.
   *
   * Returns this for method chaining.
   *
   * @param args Arguments passed to ResponseCookies.set(). Typically:
   *   - name: string - The cookie name
   *   - value: string - The cookie value
   *   - options: CookieOptions - Cookie attributes (httpOnly, secure, sameSite, etc.)
   *
   * @returns Returns this for method chaining (fluent API).
   *
   * @example
   * ```typescript
   * cookies
   *   .set("session", "token", { httpOnly: true, secure: true })
   *   .set("preferences", "dark-mode", { httpOnly: false });
   * ```
   */
  set(...args: Parameters<ResponseCookies["set"]>) {
    this.responseCookies.set(...args);
    return this;
  }

  /**
   * Deletes a cookie by name.
   *
   * This method removes a cookie from the response by setting an expiration time
   * in the past.
   *
   * @param args Arguments passed to ResponseCookies.delete(). Typically:
   *   - name: string - The cookie name
   *   - options?: { path?: string, domain?: string } - Cookie removal options
   *
   * @returns Returns this for method chaining (fluent API).
   *
   * @example
   * ```typescript
   * cookies
   *   .delete("cookieName");
   * ```
   */
  delete(...nameOrOptionsArgs: Parameters<ResponseCookies["delete"]>) {
    const nameOrOptions = nameOrOptionsArgs[0];

    if (typeof nameOrOptions === "string") {
      this.responseCookies.set(nameOrOptions, '', {
        maxAge: 0,
      });
    } else {
      const { name, ...restOptions } = nameOrOptions;
      this.responseCookies.set(name, '', {
        ...restOptions,
        maxAge: 0,
      });
    }

    return this;
  }
}
