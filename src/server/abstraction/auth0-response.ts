import { Auth0ResponseCookies } from "./auth0-response-cookies.js";

/**
 * An abstract representation of an HTTP response.
 */
export abstract class Auth0Response<TResponse = any> {
  constructor(public res: TResponse) {}

  abstract getCookies(): Auth0ResponseCookies;
  abstract redirect(url: string): void;
  abstract status(message: string | null, status: number): TResponse | void;
  abstract json(body: any, init?: ResponseInit): void;
  abstract addCacheControlHeadersForSession(): void;

  abstract setResponse(res: TResponse): void;

  abstract generic(body: BodyInit | null, { status, statusText, headers }: ResponseInit): void;
}
