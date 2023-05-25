import { NextResponse } from 'next/server';
import type { CookieSerializeOptions } from 'cookie';
import { Auth0Response } from '../auth0-session/http';
import Auth0NextResponseCookies from './auth0-next-response-cookies';

export default class Auth0NextResponse extends Auth0Response<NextResponse> {
  private cookies: Auth0NextResponseCookies;

  public constructor(res: NextResponse) {
    super(res);
    this.cookies = new Auth0NextResponseCookies();
  }

  public setCookie(name: string, value: string, options?: CookieSerializeOptions) {
    try {
      // Can't set multiple cookies with `res.cookies` in app dir
      // See: https://github.com/vercel/edge-runtime/issues/283
      this.cookies.setCookie(name, value, options);
    } catch (_) {
      // This runs on middleware when next/headers fails
      this.res.cookies.set(name, value, options);
    }
  }

  public clearCookie(name: string, options?: CookieSerializeOptions) {
    try {
      // Can't set multiple cookies with `res.cookies` in app dir
      // See: https://github.com/vercel/edge-runtime/issues/283
      return this.cookies.clearCookie(name, options);
    } catch (_) {
      // This runs on middleware when next/headers fails
      this.res.cookies.delete({ ...options, name, value: '' });
    }
  }

  public redirect(location: string, status = 302): void {
    const headers = new Headers({ location });
    this.res.headers.forEach((value, key) => headers.set(key, value));
    this.res = new NextResponse(null, { ...this.res, status, headers });
  }
}
