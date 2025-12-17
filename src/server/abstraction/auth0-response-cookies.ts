import { ResponseCookies } from "../cookies.js";

/**
 * A wrapper around ResponseCookies.
 */
export class Auth0ResponseCookies {
  constructor(
    private responseCookies: ResponseCookies,
  ) {}

  /**
   * Retrieves a cookie by name.
   * @param name The name of the cookie to retrieve.
   * @returns The cookie object if found, undefined otherwise.
   */
  get(name: string) {
    return this.responseCookies.get(name);
  }

  /**
   * Retrieves all cookies.
   * @returns An array of all cookies.
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
   * Sets a cookie value and syncs the change to the NextApiResponse.
   * @param args Arguments passed to ResponseCookies.set()
   */
  set(...args: Parameters<ResponseCookies["set"]>) {
    this.responseCookies.set(...args);
    return this;
  }

  /**
   * Deletes a cookie and syncs the change to the NextApiResponse.
   * @param args Arguments passed to ResponseCookies.delete()
   */
  delete(...args: Parameters<ResponseCookies["delete"]>) {
    this.responseCookies.delete(...args);
    return this;
  }
}
