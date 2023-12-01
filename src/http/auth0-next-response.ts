import { NextResponse } from 'next/server';
import type { CookieSerializeOptions } from 'cookie';
import { Auth0Response } from '../auth0-session/http';

export default class Auth0NextResponse extends Auth0Response<NextResponse> {
  public constructor(res: NextResponse) {
    /* c8 ignore next */
    super(res);
  }

  public setCookie(name: string, value: string, options?: CookieSerializeOptions) {
    this.res.cookies.set(name, value, options);
  }

  public clearCookie(name: string, options?: CookieSerializeOptions) {
    this.setCookie(name, '', { ...options, expires: new Date(0) });
  }

  public redirect(location: string, status = 302): void {
    const oldRes = this.res;
    this.res = new NextResponse(null, { status });
    oldRes.headers.forEach((value, key) => {
      this.res.headers.set(key, value);
    });
    this.res.headers.set('location', location);
    for (const cookie of oldRes.cookies.getAll()) {
      this.res.cookies.set(cookie);
    }
  }

  public setHeader(name: string, value: string) {
    this.res.headers.set(name, value);
  }

  public send204() {
    const oldRes = this.res;
    this.res = new NextResponse(null, { status: 204 });
    oldRes.headers.forEach((value, key) => {
      this.res.headers.set(key, value);
    });
  }
}
