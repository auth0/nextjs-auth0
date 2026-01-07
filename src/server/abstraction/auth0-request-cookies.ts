import { ReadonlyRequestCookies, RequestCookies } from "../cookies.js";

/**
 * A wrapper around RequestCookies to provide a unified interface for App Router.
 */
export class Auth0RequestCookies {
  constructor(
    private cookies: ReadonlyRequestCookies | RequestCookies
  ) {}

  /**
   * Retrieves a cookie by name.
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
   * @param name The name of the cookie to check.
   * @returns True if the cookie exists, false otherwise.
   */
  has(name: string): boolean {
    return this.cookies.has(name);
  }

  /**
   * Sets a cookie value.
   * @param name The name of the cookie to set.
   * @param value The value of the cookie to set.
   */
  set(name: string, value: string): void {
    this.cookies.set(name, value);
  }

  /**
   * Deletes a cookie by name.
   * @param name The name of the cookie to delete.
   */
  delete(name: string): void {
    this.cookies.delete(name);
  }
}
