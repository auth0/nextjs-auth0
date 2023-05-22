import { ServerResponse } from 'http';
import AbstractResponse from './abstract-response';
import { htmlSafe } from '../utils/errors';

export default class NodeResponse<T extends ServerResponse = ServerResponse> extends AbstractResponse<ServerResponse> {
  public constructor(public res: T) {
    super(res);
  }

  public getSetCookieHeader(): string[] {
    let cookies = this.res.getHeader('Set-Cookie') || [];
    if (!Array.isArray(cookies)) {
      cookies = [cookies as string];
    }
    return cookies;
  }

  public setSetCookieHeader(cookies: string[]): void {
    this.res.setHeader('Set-Cookie', cookies);
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
}
