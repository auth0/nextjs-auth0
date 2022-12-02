import type { IncomingMessage, ServerResponse } from 'http';
import { CookieSerializeOptions, parse, serialize } from 'cookie';

export abstract class Cookies {
  protected cookies: string[];

  constructor() {
    this.cookies = [];
  }

  set(name: string, value: string, options: CookieSerializeOptions = {}): void {
    this.cookies.push(serialize(name, value, options));
  }

  clear(name: string, options: CookieSerializeOptions = {}): void {
    const { domain, path, secure, sameSite } = options;
    const clearOptions: CookieSerializeOptions = {
      domain,
      path,
      maxAge: 0
    };
    // If SameSite=None is set, the cookie Secure attribute must also be set (or the cookie will be blocked)
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite#none
    if (sameSite === 'none') {
      clearOptions.secure = secure;
      clearOptions.sameSite = sameSite;
    }
    this.set(name, '', clearOptions);
  }

  commit(res: unknown, filterCookiePrefix?: string): void {
    let previousCookies = this.getSetCookieHeader(res);
    if (filterCookiePrefix) {
      const re = new RegExp(`^${filterCookiePrefix}(\\.\\d+)?=`);
      previousCookies = previousCookies.filter((cookie: string) => !re.test(cookie));
    }
    this.setSetCookieHeader(res, [...previousCookies, ...this.cookies]);
  }

  protected abstract getSetCookieHeader(res: unknown): string[];
  protected abstract setSetCookieHeader(res: unknown, cookies: string[]): void;
  abstract getAll(req: unknown): Record<string, string>;
}

export default class NodeCookies extends Cookies {
  protected getSetCookieHeader(res: ServerResponse): string[] {
    let cookies = res.getHeader('Set-Cookie') || [];
    if (!Array.isArray(cookies)) {
      cookies = [cookies as string];
    }
    return cookies;
  }

  protected setSetCookieHeader(res: ServerResponse, cookies: string[]): void {
    res.setHeader('Set-Cookie', cookies);
  }

  getAll(req: IncomingMessage): Record<string, string> {
    return parse(req.headers.cookie || '');
  }
}
