import Auth0RequestCookies from './auth0-request-cookies';

export default abstract class Auth0Request<Req = any> extends Auth0RequestCookies {
  protected constructor(public req: Req) {
    super();
  }

  public abstract getUrl(): string;
  public abstract getMethod(): string;
  public abstract getBody(): Promise<Record<string, string> | string> | Record<string, string> | string;
}
