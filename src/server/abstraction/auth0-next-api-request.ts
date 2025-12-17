import { NextApiRequest } from "next";
import { Auth0RequestCookies } from "./auth0-request-cookies.js";
import { Auth0Request } from "./auth0-request.js";

/**
 * An implementation of Auth0Request for Next.js' NextApiRequest.
 */
export class Auth0NextApiRequest extends Auth0Request<NextApiRequest> {
  public constructor(req: NextApiRequest) {
    /* c8 ignore next */
    super(req);
  }

  /**
   * Retrieves the full URL of the request.
   * @returns The URL object representing the request URL.
   */
  public getUrl(): URL {
    return new URL(`${process.env.APP_BASE_URL}${this.req.url}`);
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
   * @returns The body of the request, either as a string or an object.
   */
  public getBody(): Record<string, string> {
    return this.req.body;
  }

  /**
   * Retrieves the headers of the request.
   * @returns The Headers object representing the request headers.
   */
  public getHeaders(): Headers {
    return new Headers(this.req.headers as Record<string, string>);
  }

  /**
   * Clones the underlying NextApiRequest.
   * @returns A cloned NextApiRequest object.
   */
  public clone(): NextApiRequest {
    return this.req;
  }

  /**
   * Retrieves the cookies from the request.
   * @returns An Auth0RequestCookies object representing the request cookies.
   */
  public getCookies(): Auth0RequestCookies {
    return new Auth0RequestCookies(this.req.cookies as Record<string, string>);
  }
}
