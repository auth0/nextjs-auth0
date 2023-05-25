import { cookies } from 'next/headers';
import type { CookieSerializeOptions } from 'cookie';
import { Auth0ResponseCookies } from '../auth0-session/http';

export default class Auth0NextResponseCookies extends Auth0ResponseCookies {
  public constructor() {
    super();
  }

  public setCookie(name: string, value: string, options?: CookieSerializeOptions) {
    const cookieSetter = cookies();
    try {
      cookieSetter.set({ ...options, name, value });
    } catch (_) {
      console.warn('cant set cookies in app dir pages or server components');
    }
  }

  public clearCookie(name: string, options?: CookieSerializeOptions) {
    const cookieSetter = cookies();
    // @ts-ignore see: https://github.com/vercel/next.js/pull/50052
    cookieSetter.delete({ ...options, name, value: '' });
  }
}
