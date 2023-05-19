import { AbstractResponse } from '../auth0-session/http';
import { NextResponse } from 'next/server';

export default class Auth0NextResponse extends AbstractResponse<NextResponse> {
  public constructor(res: NextResponse) {
    super(res);
  }
  protected getSetCookieHeader(): string[] {
    const value = this.res.headers.get('set-cookie');
    return value?.split(', ') || [];
  }
  protected setSetCookieHeader(cookies: string[]): void {
    this.res.headers.set('set-cookie', cookies.join(', '));
  }
  public redirect(location: string, status = 302): void {
    const headers = new Headers({ ...this.res.headers, location: this.res.headers.get('location') || location });
    this.res = NextResponse.next({ ...this.res, status, headers });
  }
}
