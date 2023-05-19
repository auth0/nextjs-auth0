import { AbstractRequest } from '../auth0-session/http';
import { NextApiRequest } from 'next';

export default class Auth0NextApiRequest extends AbstractRequest<NextApiRequest> {
  public constructor(req: NextApiRequest) {
    super(req);
  }

  public getUrl(): string {
    return this.req.url as string;
  }
  public getMethod(): string {
    return this.req.method as string;
  }
  public getBody(): Record<string, string> {
    return this.req.body;
  }
  public getCookies(): Record<string, string> {
    return this.req.cookies as Record<string, string>;
  }
}
