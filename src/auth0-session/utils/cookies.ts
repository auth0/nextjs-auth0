import { IncomingMessage, ServerResponse } from 'http';
import { CookieSerializeOptions, parse, serialize } from 'cookie';

export interface ICookies {
  set(name: string, value: string, options?: CookieSerializeOptions): void;
  clear(name: string, options?: CookieSerializeOptions): void;
  commit(res: unknown, filterCookiePrefix?: string): void;
  getAll(req: unknown): Record<string, string>;
}

export default class Cookies implements ICookies {
  private cookies: string[];

  constructor() {
    this.cookies = [];
  }

  set(name: string, value: string, options: CookieSerializeOptions = {}) {
    this.cookies.push(serialize(name, value, options));
  }

  clear(name: string, options: CookieSerializeOptions = {}) {
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

  commit(res: ServerResponse, filterCookiePrefix?: string) {
    let previousCookies = res.getHeader('Set-Cookie') || [];
    if (!Array.isArray(previousCookies)) {
      previousCookies = [previousCookies as string];
    }
    if (filterCookiePrefix) {
      const re = new RegExp(`^${filterCookiePrefix}(\\.\\d+)?=`);
      previousCookies = previousCookies.filter((cookie: string) => !re.test(cookie));
    }
    res.setHeader('Set-Cookie', [...previousCookies, ...this.cookies]);
  }

  getAll(req: IncomingMessage) {
    return parse(req.headers.cookie || '');
  }
}
