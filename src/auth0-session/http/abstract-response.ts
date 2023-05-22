import { CookieSerializeOptions, serialize } from 'cookie';

export default abstract class AbstractResponse<Res = any> {
  protected constructor(public res: Res) {}

  public setCookie(name: string, value: string, options: CookieSerializeOptions = {}): void {
    let previousCookies = this.getSetCookieHeader();

    this.setSetCookieHeader([...previousCookies, serialize(name, value, options)]);
  }

  public clearCookie(name: string, options: CookieSerializeOptions = {}): void {
    const { domain, path, secure, sameSite } = options;
    const clearOptions: CookieSerializeOptions = {
      domain,
      path,
      maxAge: 0
    };
    // If SameSite=None is set, the cookie Secure attribute must also be set (or the cookie will be blocked)
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite#none
    if (sameSite === 'none') {
      clearOptions.secure = secure;
      clearOptions.sameSite = sameSite;
    }
    this.setCookie(name, '', clearOptions);
  }

  abstract getSetCookieHeader(): string[];
  abstract setSetCookieHeader(cookies: string[]): void;
  public abstract redirect(location: string, status?: number): void;
}
