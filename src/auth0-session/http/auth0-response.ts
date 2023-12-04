import Auth0ResponseCookies from './auth0-response-cookies';

export default abstract class Auth0Response<Res = any> extends Auth0ResponseCookies {
  protected constructor(public res: Res) {
    super();
  }

  public abstract redirect(location: string, status?: number): void;

  public abstract send204(): void;

  public abstract setHeader(name: string, value: string): void;
}
