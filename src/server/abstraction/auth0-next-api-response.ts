import { NextApiResponse } from "next";

import { Auth0ApiResponseCookies } from "./auth0-api-response-cookies.js";
import { Auth0ResponseCookies } from "./auth0-response-cookies.js";
import { Auth0Response } from "./auth0-response.js";

/**
 * An implementation of Auth0Request for Next.js' NextApiRequest.
 */
export class Auth0NextApiResponse extends Auth0Response<NextApiResponse> {
  public constructor(res: NextApiResponse) {
    /* c8 ignore next */
    super(res);
  }

  /**
   * Retrieves the cookies from the response.
   * @returns An Auth0ResponseCookies object representing the response cookies.
   */
  getCookies(): Auth0ResponseCookies {
    return new Auth0ApiResponseCookies(this.res);
  }

  /**
   * Redirects the response to the specified URL.
   * @param url The URL to redirect to.
   */
  redirect(url: string): void {
    console.log('Redirect response being sent to ' + url);
    this.res.redirect(url);
    //this.res.end();
  }

  /**
   * Sets the status code of the response.
   * @param status The HTTP status code to set.
   */
  status(message: string | null, status: number): void {
    console.log('Status response being sent');
    this.res.send(message);
    this.res.status(status);
    //this.res.end();
  }

  /**
   * Sends a JSON response.
   * @param body The body of the response.
   */
  json(body: any, responseInit?: ResponseInit): void {
    console.log('JSON response being sent');
    this.res.json(body);
    this.#setResponseInit(responseInit);
    //this.res.end();
  }

  /**
   * Adds cache control headers to the response to prevent caching of session data.
   */
  addCacheControlHeadersForSession(): void {
    console.log('Adding no-cache headers to response');
    this.res.setHeader(
      "Cache-Control",
      "private, no-cache, no-store, must-revalidate, max-age=0"
    );
    this.res.setHeader("Pragma", "no-cache");
    this.res.setHeader("Expires", "0");
  }

  generic(body: BodyInit | null, responseInit: ResponseInit): void {
    console.log('Generic response being sent');
    this.res.json(body);
    this.#setResponseInit(responseInit);
    //this.res.end();
  }

  setResponse(res: NextApiResponse<unknown>): void {
    // A bit ugly, but NextApiResponse does not need this ????
    // TODO: later, first lets fix NextResponse implementation
  }

  #setResponseInit(init?: ResponseInit) {
    if (init?.status) {
      this.res.status(init.status);
    }
    if (init?.statusText) {
      this.res.statusMessage = init.statusText;
    }

    if (init?.headers) {
      for (const [key, value] of Object.entries(init.headers)) {
        if (value) {
          this.res.setHeader(key, value);
        }
      }
    }
  }
}
