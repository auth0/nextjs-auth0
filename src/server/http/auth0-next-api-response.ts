import { NextApiResponse } from "next";

import { Auth0ApiResponseCookies } from "./auth0-api-response-cookies.js";
import { Auth0ResponseCookies } from "./auth0-response-cookies.js";
import { Auth0Response } from "./auth0-response.js";

/**
 * An implementation of Auth0Response for Next.js' NextApiResponse.
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
  redirect(url: string) {
    this.res = this.res.redirect(url);
    return this;
  }

  /**
   * Sets the status code of the response.
   * @param status The HTTP status code to set.
   */
  status(message: string | null, status: number) {
    this.res = this.res.status(status);
    this.res.send(message);

    return this;
  }

  /**
   * Sends a JSON response.
   * @param body The body to send as JSON.
   * @param init Optional response initialization options.
   */
  json(body: any, init?: ResponseInit) {
    if (init) {
      this.#applyResponseInit(this.res, init);
    }
    this.res.json(body);

    return this;
  }

  /**
   * Adds cache control headers for session handling.
   */
  addCacheControlHeadersForSession(): void {
    this.res = this.res
      .setHeader("Cache-Control", "no-store")
      .setHeader(
        "Cache-Control",
        "private, no-cache, no-store, must-revalidate, max-age=0"
      )
      .setHeader("Pragma", "no-cache")
      .setHeader("Expires", "0");
  }

  /**
   * Sets the response object (no-op for API routes as response is mutated directly).
   * @param res The response object to set.
   */
  setResponse(res: NextApiResponse): void {
    this.res = res;
  }

  /**
   * Sends a generic response with body and init options.
   * @param body The body to send.
   * @param init Response initialization options.
   */
  generic(body: BodyInit | null, init: ResponseInit) {
    this.#applyResponseInit(this.res, init);
    this.res.send(body);

    return this;
  }

  #applyResponseInit(res: NextApiResponse, init: ResponseInit) {
    if (init.status) {
      res.statusCode = init.status;
    }

    if (init.statusText) {
      res.statusMessage = init.statusText;
    }

    if (init.headers) {
      const headers = Object.entries(init.headers);
      headers.forEach(([key, value]) => {
        res.setHeader(key, value as string);
      });
    }
  }
}
