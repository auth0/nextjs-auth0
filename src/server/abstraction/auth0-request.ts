import { NextApiRequest } from "next";
import { Auth0RequestCookies } from "./auth0-request-cookies.js";

/**
 * An abstract representation of an HTTP request.
 */
export abstract class Auth0Request<TRequest = any> {
  protected constructor(public req: TRequest) {}
  
  public abstract getUrl(): URL;
  public abstract getMethod(): string;
  public abstract getBody():
    | Promise<Record<string, string> | string>
    | Record<string, string>
    | string;

  public abstract getHeaders(): Headers;
  public abstract clone(): Request | NextApiRequest;
  public abstract getCookies(): Auth0RequestCookies;
}
