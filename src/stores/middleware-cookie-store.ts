import { NextRequest, NextResponse } from 'next/server';
import { CookieSerializeOptions } from 'cookie';
import AbstractCookieStore from '../auth0-session/stores/abstract-cookie-store';

export default class MiddlewareCookieStore extends AbstractCookieStore {
  protected getCookies(req: NextRequest) {
    return Array.from(req.cookies.keys()).reduce((memo: { [key: string]: string }, key) => {
      memo[key] = req.cookies.get(key) as string;
      return memo;
    }, {});
  }

  protected setCookie(res: NextResponse, name: string, value: string, opts: CookieSerializeOptions) {
    res.cookies.set(name, value, opts);
  }

  protected clearCookie(res: NextResponse, name: string, opts: CookieSerializeOptions) {
    res.cookies.delete(name, opts);
  }
}
