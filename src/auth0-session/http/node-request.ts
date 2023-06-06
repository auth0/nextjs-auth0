import { IncomingMessage } from 'http';
import { parse } from 'cookie';
import Auth0Request from './auth0-request';

export default class NodeRequest extends Auth0Request<IncomingMessage> {
  public constructor(public req: IncomingMessage) {
    /* c8 ignore next */
    super(req);
  }

  public getUrl() {
    return this.req.url as string;
  }

  public getMethod() {
    return this.req.method as string;
  }

  public getBody() {
    return (this.req as IncomingMessage & { body: Record<string, string> }).body;
  }

  public getCookies(): Record<string, string> {
    return parse(this.req.headers.cookie || '');
  }
}
