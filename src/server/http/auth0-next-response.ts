import { NextResponse } from "next/server.js";

import { Auth0ResponseCookies } from "./auth0-response-cookies.js";
import { Auth0Response } from "./auth0-response.js";

/**
 * An implementation of Auth0Response for Next.js' NextResponse.
 *
 * This class wraps NextResponse and provides a unified interface for setting responses,
 * managing cookies, and handling redirects. It maintains a copy of headers from the
 * previous response to support middleware patterns where responses are modified before
 * being returned.
 *
 * @example
 * ```typescript
 * const res = new Auth0NextResponse(NextResponse.next());
 * res.redirect("https://example.com/callback");
 * ```
 */
export class Auth0NextResponse extends Auth0Response<NextResponse> {
  public constructor(res: NextResponse) {
    /* c8 ignore next */
    super(res);
  }

  /**
   * Retrieves the cookies from the response.
   * @returns An Auth0ResponseCookies object representing the response cookies.
   */
  public getCookies(): Auth0ResponseCookies {
    return new Auth0ResponseCookies(this.res.cookies);
  }

  /**
   * Redirects the response to the specified URL.
   *
   * This method creates a redirect response and merges headers.
   *
   * @param url - The URL to redirect to.
   */
  public redirect(url: string) {
    this.res = this.#mergeHeaders(this.res, NextResponse.redirect(url));

    return this;
  }

  /**
   * Sets the HTTP status code of the response.
   *
   * This method creates a new response with the specified status code and message.
   *
   * @param message - The response body as a string or null.
   * @param status - The HTTP status code (e.g., 200, 401, 500).
   *
   * @example
   * ```typescript
   * res.status("Unauthorized", 401);
   * ```
   */
  public status(message: string | null, status: number) {
    const body = status === 204 ? null : message;
    this.res = this.#mergeHeaders(this.res, new NextResponse(body, { status }));

    return this;
  }

  /**
   * Sends a JSON response with the specified body.
   *
   * @param body - The body of the JSON response.
   * @param init - Optional response initialization options (status, headers, etc.).
   *
   * @example
   * ```typescript
   * res.json({ error: "Invalid token" }, { status: 401 });
   * ```
   */
  public json(body: any, init?: ResponseInit) {
    this.res = this.#mergeHeaders(this.res, NextResponse.json(body, init));

    return this;
  }

  public generic(body: any, init?: ResponseInit) {
    this.res = this.#mergeHeaders(this.res, new NextResponse(body, init));

    return this;
  }

  /**
   * Sets the response to a new NextResponse instance, merging headers.
   *
   * @param res - The new NextResponse instance to set.
   *
   * @example
   * ```typescript
   * const newRes = NextResponse.redirect("/login");
   * auth0Res.setResponse(newRes);
   * ```
   */
  setResponse(res: NextResponse<unknown>): void {
    this.res = this.#mergeHeaders(this.res, res);
  }

  /**
   * Merges headers from the old response into the new response.
   *
   * This is used because we can apply cookie and cache changes prior to ending the response.
   *
   * @param oldRes - The old NextResponse instance.
   * @param newRes - The new NextResponse instance.
   * @returns The new NextResponse with merged headers.
   */
  #mergeHeaders(oldRes: NextResponse, newRes: NextResponse) {
    // When a Cache-Control, Pragma, or Expires header was defined on the old response,
    // we ensure to copy it to the new response.
    const headers = ["Cache-Control", "Pragma", "Expires"];

    headers.forEach(name => {
      const originalHeader = oldRes.headers.get(name);

      if (originalHeader) {
        newRes.headers.set(name, originalHeader);
      }
    });

    // If we have cookies defined on the response,
    // ensure to carry them over to the new response.
    oldRes.cookies.getAll().forEach(cookie => {
      newRes.cookies.set(cookie.name, cookie.value, cookie);
    })

    return newRes;
  }

  /**
   * Adds cache control headers to the response to prevent caching of session data.
   *
   * This method sets multiple cache control headers to ensure that sensitive session
   * data (like authentication tokens or user info) is never cached by browsers,
   * proxies, or CDNs.
   *
   * Headers set:
   * - Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0
   * - Pragma: no-cache (for HTTP/1.0 compatibility)
   * - Expires: 0 (for older browser compatibility)
   *
   * This should be called for any response containing authenticated user data.
   *
   * @example
   * ```typescript
   * const res = new Auth0NextResponse(NextResponse.next());
   * res.json(user);
   * res.addCacheControlHeadersForSession();
   * ```
   */
  addCacheControlHeadersForSession(): void {
    this.res.headers.set(
      "Cache-Control",
      "private, no-cache, no-store, must-revalidate, max-age=0"
    );
    this.res.headers.set("Pragma", "no-cache");
    this.res.headers.set("Expires", "0");
  }
}
