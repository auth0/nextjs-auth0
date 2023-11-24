import { ServerResponse } from 'http';
import { CookieSerializeOptions, serialize } from 'cookie';
import Auth0Response from './auth0-response';
import { htmlSafe } from '../utils/errors';

export default class NodeResponse<T extends ServerResponse = ServerResponse> extends Auth0Response<ServerResponse> {
  public constructor(public res: T) {
    /* c8 ignore next */
    super(res);
  }

  public setCookie(name: string, value: string, options?: CookieSerializeOptions) {
    let cookies = this.res.getHeader('Set-Cookie') || [];
    if (!Array.isArray(cookies)) {
      cookies = [cookies as string];
    }

    this.res.setHeader('Set-Cookie', [
      ...cookies.filter((cookie) => !cookie.startsWith(`${name}=`)),
      serialize(name, value, options)
    ]);
  }

  public redirect(location: string, status = 302): void {
    if (this.res.writableEnded) {
      return;
    }
    this.res.writeHead(status, {
      Location: this.res.getHeader('Location') || location
    });
    this.res.end(htmlSafe(location));
  }

  public send204(): void {
    this.res.statusCode = 204;
    this.res.end();
  }

  public setHeader(name: string, value: string): void {
    this.res.setHeader(name, value);
  }
}
