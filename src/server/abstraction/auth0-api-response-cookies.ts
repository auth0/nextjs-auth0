import { NextApiResponse } from "next";

import { ResponseCookies } from "../cookies.js";
import { Auth0ResponseCookies } from "./auth0-response-cookies.js";

/**
 * A wrapper around Auth0ResponseCookies that syncs cookie changes
 * back to the NextApiResponse.
 *
 * The problem: ResponseCookies operates on a Headers object, but changes to this
 * Headers object don't automatically propagate to NextApiResponse's internal headers.
 *
 * This class solves the issue by intercepting write operations (set, delete) and
 * syncing the changes back to the NextApiResponse after each mutation.
 */
export class Auth0ApiResponseCookies extends Auth0ResponseCookies {
  private readonly headers: Headers;
  constructor(private res: NextApiResponse) {
    const headers = new Headers(res.getHeaders() as Record<string, string>);
    const responseCookies = new ResponseCookies(headers);
    super(responseCookies);

    this.headers = headers;
  }
  /**
   * Sets a cookie value and syncs the change to the NextApiResponse.
   * @param args Arguments passed to ResponseCookies.set()
   */
  set(...args: Parameters<ResponseCookies["set"]>) {
    console.log('Setting cookie:', args);
    super.set(...args);
    this.syncToResponse();
    return this;
  }

  /**
   * Deletes a cookie and syncs the change to the NextApiResponse.
   * @param args Arguments passed to ResponseCookies.delete()
   */
  delete(...args: Parameters<ResponseCookies["delete"]>) {
    console.log('Deleting cookie:', args);
    super.delete(...args);
    this.syncToResponse();
    return this;
  }

  /**
   * Syncs cookie changes from the internal Headers object to the NextApiResponse.
   *
   * This method extracts the 'set-cookie' header from the internal Headers object
   * and applies it to the NextApiResponse, ensuring that all cookie mutations
   * are reflected in the actual HTTP response.
   */
  private syncToResponse(): void {
    // The Headers API provides getSetCookie() to properly handle multiple set-cookie headers
    // Each cookie must be a separate header value, not comma-separated
    const setCookieHeaders = (this.headers as any).getSetCookie?.() || [];

    console.log('syncing cookies to NextApiResponse');
    console.log('headersSent: ' + this.res.headersSent)

    if (setCookieHeaders.length > 0) {
      // NextApiResponse's setHeader accepts either a string or an array of strings
      // When it's an array, each element becomes a separate header value
      console.log('setCookieHeaders');  
      this.res.setHeader("Set-Cookie", setCookieHeaders ?? 'TEST');
    } else {
      console.log('Removing set-cookie');
      // If there are no set-cookie headers, clear them from the response
      this.res.removeHeader("Set-Cookie");
    }

    // Does res still have the cookie at this point?
    console.log(this.res.getHeader('Cookie')); // undefined
    // What about set-cookie header?
    console.log(this.res.getHeader("Set-Cookie")); // undefined
  }
}
