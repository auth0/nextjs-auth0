import { IncomingMessage } from 'http';
import { parse } from 'cookie';
import AbstractRequest from './abstract-request';

export default class NodeRequest extends AbstractRequest<IncomingMessage> {
  public constructor(protected req: IncomingMessage) {
    super(req);
  }

  public getUrl() {
    return this.req.url as string;
  }

  public getMethod() {
    return this.req.method as string;
  }

  public getBody() {
    return (this.req as any).body as Record<string, string>;
  }

  public getCookies(): Record<string, string> {
    return parse(this.req.headers.cookie || '');
  }
}
