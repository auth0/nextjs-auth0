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
    return req.cookies.getAll().reduce((memo, { name, value }) => ({ ...memo, [name]: value }), {});
  }
}
