import type {
  CookieHandler,
  CookieSerializeOptions
} from "@auth0/auth0-server-js";
import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";

export type Auth0CookieContext = {
  reqCookies: RequestCookies;
  resCookies?: ResponseCookies;
};

export class Auth0CookieHandler implements CookieHandler<Auth0CookieContext> {
  // Optional cookie `Domain` to stamp on every write / delete this handler
  // performs. The engine's session (`StatelessStateStore`) write path calls
  // `setCookie` / `deleteCookie` with cookie options that never include a
  // domain (the engine's private `#getCookieOptions` only sets
  // httpOnly/sameSite/secure/path), so a consumer that configures a cookie
  // domain (`session.cookie.domain` / `AUTH0_COOKIE_DOMAIN`) has no other seam
  // to reach it. Injecting it here is the one place that covers the native
  // session-cookie write AND its logout deletion (browsers only delete a cookie
  // when the delete's `Domain` matches the one it was written with).
  //
  // When `undefined` (no domain configured), this handler is a verbatim
  // passthrough, preserving the exact "no domain by default" behavior.
  readonly #domain?: string;

  constructor(domain?: string) {
    this.#domain = domain;
  }

  getCookie(name: string, ctx?: Auth0CookieContext): string | undefined {
    return ctx?.reqCookies.get(name)?.value;
  }

  getCookies(ctx?: Auth0CookieContext): Record<string, string> {
    if (!ctx) return {};
    const result: Record<string, string> = {};
    for (const cookie of ctx.reqCookies.getAll()) {
      result[cookie.name] = cookie.value;
    }
    return result;
  }

  setCookie(
    name: string,
    value: string,
    options?: CookieSerializeOptions,
    ctx?: Auth0CookieContext
  ): void {
    if (!ctx?.resCookies) return;
    ctx.resCookies.set(name, value, this.#withDomain(options));
    ctx.reqCookies.set(name, value);
  }

  deleteCookie(
    name: string,
    ctx?: Auth0CookieContext,
    options?: CookieSerializeOptions
  ): void {
    if (!ctx?.resCookies) return;
    const opts = this.#withDomain(options);
    if (opts) {
      ctx.resCookies.delete({ name, ...opts });
    } else {
      ctx.resCookies.delete(name);
    }
    ctx.reqCookies.delete(name);
  }

  // Returns `options` unchanged when no handler domain is configured (verbatim
  // passthrough, including the `undefined` case so `deleteCookie` keeps its
  // name-only delete). When a domain is configured, fills it in only if the
  // caller did not already specify one, so a per-call `domain` always wins.
  #withDomain(
    options?: CookieSerializeOptions
  ): CookieSerializeOptions | undefined {
    if (this.#domain === undefined) {
      return options;
    }
    if (options?.domain !== undefined) {
      return options;
    }
    return { ...(options ?? {}), domain: this.#domain };
  }
}
