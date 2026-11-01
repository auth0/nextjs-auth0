import type {
  CookieHandler,
  CookieSerializeOptions
} from "@auth0/auth0-server-js";

import type { CookieContext } from "./context.js";

export interface NextCookieHandlerOptions {
  /**
   * The session cookie name (`session.cookie.name`, default `__session`). The anonymous store's
   * handler gets the anonymous cookie name here (`anonymousSession.cookie.name`).
   */
  sessionName: string;
  /**
   * Cookie domain added to every session cookie write and delete.
   */
  domain?: string;
  /**
   * When `true`, session cookies are written without `maxAge`, so they end with the browser session.
   */
  transient?: boolean;
}

/**
 * Gives the engine read access to the request cookies and write access to the response cookies.
 *
 * - Adds the cookie settings the engine cannot set itself (`domain`, `transient`) to session cookies.
 * - Every other cookie (for example `__txn_*`) is passed through unchanged.
 *
 * Session cookies are `name` and its chunks `name__<number>`, the names nextjs uses: the stateless
 * store stores the engine's `name.<number>` chunks under them (`withChunkCookieNames`).
 *
 * `getCookies()` returns every request cookie. The engine's stores match their own chunks strictly,
 * so unrelated cookies are never joined into the session or deleted.
 */
export class NextCookieHandler implements CookieHandler<CookieContext> {
  readonly #sessionName: string;
  readonly #chunkRegex: RegExp;
  readonly #domain?: string;
  readonly #transient: boolean;

  constructor({ sessionName, domain, transient }: NextCookieHandlerOptions) {
    this.#sessionName = sessionName;
    this.#chunkRegex = new RegExp(
      `^${sessionName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}__\\d+$`
    );
    this.#domain = domain;
    this.#transient = transient ?? false;
  }

  getCookie(name: string, ctx?: CookieContext): string | undefined {
    return ctx?.reqCookies.get(name)?.value;
  }

  getCookies(ctx?: CookieContext): Record<string, string> {
    const result: Record<string, string> = {};
    if (!ctx) {
      return result;
    }

    for (const { name, value } of ctx.reqCookies.getAll()) {
      result[name] = value;
    }
    return result;
  }

  setCookie(
    name: string,
    value: string,
    options?: CookieSerializeOptions,
    ctx?: CookieContext
  ): void {
    let finalOptions = options;
    if (this.#isSessionCookie(name)) {
      finalOptions = this.#withDomain(options);
      if (this.#transient) {
        const { maxAge: _maxAge, ...rest } = finalOptions ?? {};
        finalOptions = rest;
      }
    }

    if (this.#write(ctx, name, value, finalOptions)) {
      // Read-after-write: later reads in the same request see the new value. Skipped when both
      // stores are the same `cookies()` store (Server Actions): a second bare set() would
      // overwrite the first and drop HttpOnly, Secure, SameSite and Max-Age.
      if (!isSameStore(ctx!)) {
        ctx!.reqCookies.set(name, value);
      }
    }
  }

  deleteCookie(
    name: string,
    ctx?: CookieContext,
    options?: CookieSerializeOptions
  ): void {
    const finalOptions = this.#isSessionCookie(name)
      ? this.#withDomain(options)
      : options;

    // Deleted by writing an empty value with `maxAge: 0` and the cookie's own attributes, as on
    // nextjs: browsers only delete a cookie when `Domain` and `Path` match the original write.
    if (this.#write(ctx, name, "", { ...finalOptions, maxAge: 0 })) {
      // Same guard as setCookie: a bare delete() would drop the domain from the deletion.
      if (!isSameStore(ctx!)) {
        ctx!.reqCookies.delete(name);
      }
    }
  }

  /**
   * Writes to the response cookies. Returns `false` when nothing was written.
   */
  #write(
    ctx: CookieContext | undefined,
    name: string,
    value: string,
    options?: CookieSerializeOptions
  ): boolean {
    if (!ctx?.resCookies) {
      return false;
    }

    try {
      ctx.resCookies.set(name, value, options);
      return true;
    } catch (e) {
      if (!ctx.ignoreWriteErrors) {
        throw e;
      }
      ctx.writeFailed = true;
      return false;
    }
  }

  #isSessionCookie(name: string): boolean {
    return name === this.#sessionName || this.#chunkRegex.test(name);
  }

  #withDomain(
    options?: CookieSerializeOptions
  ): CookieSerializeOptions | undefined {
    if (this.#domain === undefined || options?.domain !== undefined) {
      return options;
    }
    return { ...options, domain: this.#domain };
  }
}

function isSameStore(ctx: CookieContext): boolean {
  return (ctx.reqCookies as unknown) === (ctx.resCookies as unknown);
}
