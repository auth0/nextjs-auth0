import { Auth0Request } from '../auth0-session/http';
import { NextRequest } from 'next/server';

export default class Auth0NextRequest extends Auth0Request<NextRequest> {
  public constructor(req: NextRequest) {
    /* c8 ignore next */
    super(req);
  }

  public getUrl(): string {
    return this.req.url as string;
  }
  public getMethod(): string {
    return this.req.method as string;
  }
  public async getBody(): Promise<Record<string, string> | string> {
    return this.req.text();
  }
  public getCookies(): Record<string, string> {
    const { cookies } = this.req;
    if (typeof cookies.getAll === 'function') {
      return this.req.cookies.getAll().reduce((memo, { name, value }) => ({ ...memo, [name]: value }), {});
    }
    // Edge cookies before Next 13.0.1 have no `getAll` and extend `Map`.
    const legacyCookies = cookies as unknown as Map<string, string>;
    return Array.from(legacyCookies.keys()).reduce((memo: { [key: string]: string }, key) => {
      memo[key] = legacyCookies.get(key) as string;
      return memo;
    }, {});
  }
}
