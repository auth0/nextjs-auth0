import { CookieSerializeOptions } from 'cookie';

export default abstract class Auth0ResponseCookies {
  public abstract setCookie(name: string, value: string, options?: CookieSerializeOptions): void;

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
}
