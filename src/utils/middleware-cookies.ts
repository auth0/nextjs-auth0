import { Cookies } from '../auth0-session/utils/cookies';
import { NextRequest, NextResponse } from 'next/server';

export default class MiddlewareCookies extends Cookies {
  protected getSetCookieHeader(res: NextResponse): string[] {
    const value = res.headers.get('set-cookie');
    return value?.split(', ') || [];
  }

  protected setSetCookieHeader(res: NextResponse, cookies: string[]): void {
    res.headers.set('set-cookie', cookies.join(', '));
  }

  getAll(req: NextRequest): Record<string, string> {
    const { cookies } = req;
    if (typeof cookies.getAll === 'function') {
      return req.cookies.getAll().reduce((memo, { name, value }) => ({ ...memo, [name]: value }), {});
    }
    // Edge cookies before Next 13.0.1 have no `getAll` and extend `Map`.
    const legacyCookies = cookies as unknown as Map<string, string>;
    return Array.from(legacyCookies.keys()).reduce((memo: { [key: string]: string }, key) => {
      memo[key] = legacyCookies.get(key) as string;
      return memo;
    }, {});
  }
}
