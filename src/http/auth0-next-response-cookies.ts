import { cookies } from 'next/headers';
import type { CookieSerializeOptions } from 'cookie';
import { Auth0ResponseCookies } from '../auth0-session/http';

let warned = false;

const warn = () => {
  /* c8 ignore next 8 */
  if (process.env.NODE_ENV === 'development' && !warned) {
    console.warn(
      'nextjs-auth0 is attempting to set cookies from a server component,' +
        'see https://github.com/auth0/nextjs-auth0#important-limitations-of-the-app-directory'
    );
    warned = true;
  }
};

export default class Auth0NextResponseCookies extends Auth0ResponseCookies {
  public constructor() {
    super();
  }

  public setCookie(name: string, value: string, options?: CookieSerializeOptions) {
    const cookieSetter = cookies();
    try {
      cookieSetter.set({ ...options, name, value });
    } catch (_) {
      warn();
    }
  }

  public clearCookie(name: string, options?: CookieSerializeOptions) {
    const cookieSetter = cookies();
    try {
      cookieSetter.delete({ ...options, name, value: '' });
    } catch (_) {
      warn();
    }
  }
}
