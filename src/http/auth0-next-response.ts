import { AbstractResponse } from '../auth0-session/http';
import { NextResponse } from 'next/server';

export default class Auth0NextResponse extends AbstractResponse<NextResponse> {
  public constructor(res: NextResponse) {
    super(res);
  }
  public getSetCookieHeader(): string[] {
    const value = this.res.headers.get('set-cookie');
    return value?.split(', ') || [];
  }
  public setSetCookieHeader(cookies: string[]): void {
    if (cookies.length) {
      this.res.headers.set('set-cookie', cookies.join(', '));
    }
  }
  public redirect(location: string, status = 302): void {
    const headers = new Headers({ location });
    this.res.headers.forEach((value, key) => headers.set(key, value));
    this.res = new NextResponse(null, { ...this.res, status, headers });
  }
}
