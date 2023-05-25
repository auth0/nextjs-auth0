import { NextResponse } from 'next/server';
import type { CookieSerializeOptions } from 'cookie';
import { Auth0Response } from '../auth0-session/http';

export default class Auth0NextResponse extends Auth0Response<NextResponse> {
  public constructor(res: NextResponse) {
    super(res);
  }

  public setCookie(name: string, value: string, options?: CookieSerializeOptions) {
    this.res.cookies.set(name, value, options);
  }

  public clearCookie(name: string, options?: CookieSerializeOptions) {
    this.res.cookies.delete({ ...options, name, value: '' });
  }

  public redirect(location: string, status = 302): void {
    const headers = new Headers({ location });
    this.res.headers.forEach((value, key) => headers.set(key, value));
    this.res = new NextResponse(null, { ...this.res, status, headers });
  }
}
