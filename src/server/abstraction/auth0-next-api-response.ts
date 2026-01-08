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
  redirect(url: string): void {
    this.res.redirect(url);
  }

  /**
   * Sets the status code of the response.
   * @param status The HTTP status code to set.
   */
  status(message: string | null, status: number): void {
    this.res.status(status).send(message);
  }

  /**
   * Sends a JSON response.
   * @param body The body to send as JSON.
   * @param init Optional response initialization options.
   */
  json(body: any, init?: ResponseInit): void {
    if (init?.status) {
      this.res.status(init.status);
    }
    this.res.json(body);
  }

  /**
   * Adds cache control headers for session handling.
   */
  addCacheControlHeadersForSession(): void {
    this.res.setHeader("Cache-Control", "no-store");
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
  generic(body: BodyInit | null, init: ResponseInit): void {
    if (init.status) {
      this.res.status(init.status);
    }
    if (init.headers) {
      const headers = new Headers(init.headers);
      headers.forEach((value, key) => {
        this.res.setHeader(key, value);
      });
    }
    this.res.send(body);
  }
}
