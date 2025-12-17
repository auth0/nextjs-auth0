import { NextResponse } from "next/server.js";

import { Auth0ResponseCookies } from "./auth0-response-cookies.js";
import { Auth0Response } from "./auth0-response.js";

/*export function redirect(url: string, res?: Auth0Response) {
  if (res) {
    res.redirect(url);
  } else {
    return NextResponse.redirect(url);
  }
}

export function status(message: string | null, status: number, res?: Auth0Response) {
  if (res) {
    res.status(status);
  } else {
    return new NextResponse(message, {
      status
    });
  }
}

export function json(body: any, res?: Auth0Response) {
  if (res) {
    res.json(body);
  } else {
    return NextResponse.json(body);
  }
}
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

  setResponse(res: NextResponse<unknown>): void {
    this.res = this.#mergeHeaders(
      this.res,
      res,
    );
  }

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
