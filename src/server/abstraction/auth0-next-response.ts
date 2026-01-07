import { NextResponse } from "next/server.js";

import { Auth0ResponseCookies } from "./auth0-response-cookies.js";
import { Auth0Response } from "./auth0-response.js";

/**
 * An implementation of Auth0Response for Next.js' NextResponse.
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
   * @param url - The URL to redirect to.
   */
  public redirect(url: string): void {
    this.res = this.#mergeHeaders(this.res, NextResponse.redirect(url));
  }

  /**
   * Sets the HTTP status code of the response.
   * @param status - The HTTP status code to set.
   */
  public status(message: string | null, status: number): void {
    this.res = this.#mergeHeaders(
      this.res,
      new NextResponse(message, { status })
    );
  }

  /**
   * Sends a JSON response with the specified body.
   * @param body - The body of the JSON response.
   */
  public json(body: any, init?: ResponseInit): void {
    this.res = this.#mergeHeaders(this.res, NextResponse.json(body, init));
  }

  /**
   * Creates a generic response with the specified body and response init options.
   * @param body - The body of the response.
   * @param init - Response initialization options including status, statusText, and headers.
   */
  public generic(body: BodyInit, { status, statusText, headers }: ResponseInit): void {
    this.res = this.#mergeHeaders(
      this.res,
      new NextResponse(body, {
        status,
        statusText,
        headers
      })
    );
  }

  /**
   * Sets the response to a new NextResponse instance, merging headers.
   * @param res - The new NextResponse instance to set.
   */
  setResponse(res: NextResponse<unknown>): void {
    this.res = this.#mergeHeaders(this.res, res);
  }

  /**
   * Merges headers from the old response into the new response.
   * @param oldRes - The old NextResponse instance.
   * @param newRes - The new NextResponse instance.
   * @returns The new NextResponse with merged headers.
   */
  #mergeHeaders(oldRes: NextResponse, newRes: NextResponse) {
    oldRes.headers.forEach((value, key) => {
      newRes.headers.set(key, value);
    });

    return newRes;
  }

  /**
   * Adds cache control headers to the response to prevent caching of session data.
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
