import { NextRequest } from "next/server.js";

import { Auth0RequestCookies } from "./auth0-request-cookies.js";
import { Auth0Request } from "./auth0-request.js";

/**
 * An implementation of Auth0Request for Next.js' NextRequest.
 */
export class Auth0NextRequest extends Auth0Request<NextRequest> {
  public constructor(req: NextRequest) {
    /* c8 ignore next */
    super(req);
  }

  /**
   * Retrieves the full URL of the request.
   * @returns The URL object representing the request URL.
   */
  public getUrl(): URL {
    return this.req.nextUrl as URL;
  }

  /**
   * Retrieves the HTTP method of the request.
   * @returns The HTTP method as a string.
   */
  public getMethod(): string {
    return this.req.method as string;
  }

  /**
   * Retrieves the body of the request.
   * @returns A promise that resolves to the body of the request, either as a string or an object.
   */
  public async getBody(): Promise<Record<string, string> | string> {
    return this.req.text();
  }

  /**
   * Retrieves the headers of the request.
   * @returns The Headers object representing the request headers.
   */
  public getHeaders(): Headers {
    return this.req.headers;
  }

  /**
   * Clones the underlying NextRequest.
   * @returns A cloned NextRequest object.
   */
  public clone(): Request {
    return this.req.clone();
  }

  /**
   * Retrieves the cookies from the request.
   * @returns An Auth0RequestCookies object representing the request cookies.
   */
  public getCookies(): Auth0RequestCookies {
    return new Auth0RequestCookies(this.req.cookies);
  }
}
