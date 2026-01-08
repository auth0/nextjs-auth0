import { NextApiRequest } from "next";
import { RequestCookies } from "@edge-runtime/cookies";
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
    // This isn't cloning in the traditional sense, as NextApiRequest cannot be truly cloned.
    // However, we return the original request here for compatibility.

    // TODO: Test if this works as expected when using DPoP, which is when `request.clone()` is called in `#handleProxy`.
    // However, perhaps we may keep the `handleProxy` inside a proxy (undecided)? In that case, `clone()` shouldn't ever even be called on `Auth0NextApiRequest`.
    return this.req;
  }

  /**
   * Retrieves the cookies from the request.
   * @returns An Auth0RequestCookies object representing the request cookies.
   */
  public getCookies(): Auth0RequestCookies {
    // Convert plain object cookies to RequestCookies
    const headers = new Headers();
    const cookieString = Object.entries(this.req.cookies || {})
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
    if (cookieString) {
      headers.set("cookie", cookieString);
    }
    return new Auth0RequestCookies(new RequestCookies(headers));
  }
}
