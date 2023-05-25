import { cookies } from 'next/headers';
import type { CookieSerializeOptions } from 'cookie';
import { Auth0ResponseCookies } from '../auth0-session/http';

export default class Auth0NextResponseCookies extends Auth0ResponseCookies {
  public constructor() {
    super();
  }

  public setCookie(name: string, value: string, options?: CookieSerializeOptions) {
    const cookieSetter = cookies();
    cookieSetter.set({ ...options, name, value });
  }

  public clearCookie(name: string, options?: CookieSerializeOptions) {
    const cookieSetter = cookies();
    cookieSetter.delete({ ...options, name, value: '' });
  }
}
