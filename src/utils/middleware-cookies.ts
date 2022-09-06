import { Cookies } from '../auth0-session';
import { NextRequest, NextResponse } from 'next/server';

export default class MiddlewareCookies extends Cookies {
  protected getSetCookieHeader(res: NextResponse): string[] {
    const value = res.headers.get('set-cookie');
    return value !== undefined && value !== null ? value.split(', ') : [];
  }

  protected setSetCookieHeader(res: NextResponse, cookies: string[]) {
    res.headers.set('set-cookie', cookies.join(', '));
  }

  getAll(req: NextRequest): Record<string, string> {
    return Array.from(req.cookies.keys()).reduce((memo: { [key: string]: string }, key) => {
      memo[key] = req.cookies.get(key) as string;
      return memo;
    }, {});
  }
}
