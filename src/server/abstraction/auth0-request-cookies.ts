import { ReadonlyRequestCookies, RequestCookies } from "../cookies.js";

/**
 * A wrapper around various cookie representations to provide a unified interface.
 */
export class Auth0RequestCookies {
  constructor(
    private cookies:
      | ReadonlyRequestCookies
      | RequestCookies
      | Record<string, string>
  ) {}

  /**
   * Retrieves a cookie by name.
   * @param name The name of the cookie to retrieve.
   * @returns An object containing the name and value of the cookie, or undefined if not found.
   */
  get(name: string): { name: string; value: string } | undefined {
    if (this.isRequestCookies(this.cookies)) {
      const value = this.cookies.get(name);
      if (value === undefined) {
        return undefined;
      }
      return { name, value: value.value };
    } else {
      const value = this.cookies[name];
      if (value === undefined) {
        return undefined;
      }
      return { name, value };
    }
  }

  /**
   * Retrieves all cookies.
   * @returns An array of objects containing the names and values of all cookies.
   */
  getAll(): Array<{ name: string; value: string }> {
    if (this.isRequestCookies(this.cookies)) {
      return this.cookies.getAll().map((cookie) => ({
        name: cookie.name,
        value: cookie.value
      }));
    } else {
      return Object.entries(this.cookies).map(([name, value]) => ({
        name,
        value
      }));
    }
  }

  /**
   * Checks if a cookie exists by name.
   * @param name The name of the cookie to check.
   * @returns True if the cookie exists, false otherwise.
   */
  has(name: string): boolean {
    if (this.isRequestCookies(this.cookies)) {
      return this.cookies.has(name);
    } else {
      return !!this.cookies[name];
    }
  }

  /**
   * Sets a cookie value.
   * @param name The name of the cookie to set.
   * @param value The value of the cookie to set.
   */
  set(name: string, value: string): void {
    if (this.isRequestCookies(this.cookies)) {
      this.cookies.set(name, value);
    } else {
      !!this.cookies[name];
    }
  }

  /**
   * Deletes a cookie by name.
   * @param name The name of the cookie to delete.
   */
  delete(name: string): void {
    if (this.isRequestCookies(this.cookies)) {
      this.cookies.delete(name);
    } else {
      delete this.cookies[name];
    }
  }

  /**
   * Type guard to check if the cookies object is of type RequestCookies or ReadonlyRequestCookies.
   * @param cookies The cookies object to check.
   * @returns
   */
  private isRequestCookies(
    cookies: ReadonlyRequestCookies | RequestCookies | Record<string, string>
  ): cookies is RequestCookies | ReadonlyRequestCookies {
    return (cookies as RequestCookies).get !== undefined;
  }
}
