import { NextApiRequest } from "next";
import { Auth0RequestCookies } from "./auth0-request-cookies.js";

/**
 * An abstract representation of an HTTP request.
 *
 * This base class defines the interface for accessing request data without coupling
 * to specific Next.js request types. Implementations provide access to URL, HTTP method,
 * headers, body, cookies, and cloning capabilities.
 *
 * The abstraction enables:
 * - Support for multiple request types (NextRequest, NextApiRequest, etc.)
 * - Cleaner authentication logic that works with any implementation
 * - Easier testing through mock implementations
 *
 * @template TRequest The underlying request type (e.g., NextRequest, NextApiRequest)
 *
 * @example
 * ```typescript
 * // Implementation for NextRequest
 * class Auth0NextRequest extends Auth0Request<NextRequest> {
 *   public getUrl(): URL { return this.req.nextUrl; }
 *   // ... other methods
 * }
 *
 * // Usage in authentication logic
 * function handleAuth(req: Auth0Request): void {
 *   const url = req.getUrl();
 *   const method = req.getMethod();
 *   const body = await req.getBody();
 * }
 * ```
 */
export abstract class Auth0Request<TRequest = any> {
  protected constructor(public req: TRequest) {}

  /**
   * Retrieves the full URL of the request.
   *
   * @returns The URL object representing the request URL with pathname, search params, etc.
   */
  public abstract getUrl(): URL;

  /**
   * Retrieves the HTTP method of the request.
   *
   * @returns The HTTP method as a string (e.g., "GET", "POST", "PUT", "DELETE", "PATCH").
   */
  public abstract getMethod(): string;

  /**
   * Retrieves the body of the request.
   *
   * @returns Either a Promise or direct value containing the request body as text
   */
  public abstract getBody():
    | Promise<Record<string, string> | string>
    | Record<string, string>
    | string;

  /**
   * Retrieves the headers of the request.
   *
   * @returns The Headers object representing the request headers.
   */
  public abstract getHeaders(): Headers;

  /**
   * Clones the underlying request.
   *
   * @returns A cloned Request object that is independent of the original.
   */
  public abstract clone(): Request | NextApiRequest;

  /**
   * Retrieves the cookies from the request.
   *
   * @returns An Auth0RequestCookies object providing a unified interface to cookies.
   */
  public abstract getCookies(): Auth0RequestCookies;
}
