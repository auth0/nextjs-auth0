import { NextRequest } from "next/server.js";

import { Auth0RequestCookies } from "./auth0-request-cookies.js";
import { Auth0Request } from "./auth0-request.js";

/**
 * An implementation of Auth0Request for Next.js' NextRequest.
 *
 * This class wraps NextRequest and provides a unified interface for accessing request
 * properties like URL, method, headers, body, and cookies. It is used in middleware
 * and route handlers to abstract away Next.js-specific request handling.
 *
 * @example
 * ```typescript
 * const auth0Req = new Auth0NextRequest(nextRequest);
 * const url = auth0Req.getUrl();
 * const body = await auth0Req.getBody();
 * const cookies = auth0Req.getCookies();
 * ```
 */
export class Auth0NextRequest extends Auth0Request<NextRequest> {
  public constructor(req: NextRequest) {
    /* c8 ignore next */
    super(req);
  }

  /**
   * Retrieves the full URL of the request.
   *
   * @returns The URL object representing the request URL.
   *
   * @example
   * ```typescript
   * const url = auth0Req.getUrl();
   * const pathname = url.pathname;
   * const searchParams = url.searchParams;
   * ```
   */
  public getUrl(): URL {
    return new URL(this.req.nextUrl.href);
  }

  /**
   * Retrieves the HTTP method of the request.
   *
   * @returns The HTTP method as a string (e.g., "GET", "POST", "PUT", "DELETE").
   *
   * @example
   * ```typescript
   * const method = auth0Req.getMethod();
   * if (method === "POST") {
   *   // Handle POST request
   * }
   * ```
   */
  public getMethod(): string {
    return this.req.method as string;
  }

  /**
   * Retrieves the body of the request.
   *
   * This method reads the entire request body as text. The request body can only be
   * read once, so cloning the request is necessary if multiple reads are needed.
   *
   * @returns A promise that resolves to the body of the request.
   *
   * @example
   * ```typescript
   * const body = await auth0Req.getBody();
   * ```
   */
  public async getBody(): Promise<string> {
    return this.req.text();
  }

  /**
   * Retrieves the headers of the request.
   *
   * @returns The Headers object representing the request headers.
   *
   * @example
   * ```typescript
   * const headers = auth0Req.getHeaders();
   * const contentType = headers.get("content-type");
   * ```
   */
  public getHeaders(): Headers {
    return this.req.headers;
  }

  /**
   * Clones the underlying NextRequest.
   *
   * @returns A cloned NextRequest object.
   *
   * @example
   * ```typescript
   * const clonedReq = auth0Req.clone();
   * ```
   */
  public clone(): Request {
    return this.req.clone();
  }

  /**
   * Retrieves the cookies from the request.
   *
   * @returns An Auth0RequestCookies object representing the request cookies.
   *
   * @example
   * ```typescript
   * const cookies = auth0Req.getCookies();
   * const someCookie = cookies.get("cookieName");
   * if (someCookie) {
   *   // Use cookie value
   * }
   * ```
   */
  public getCookies(): Auth0RequestCookies {
    return new Auth0RequestCookies(this.req.cookies);
  }
}
