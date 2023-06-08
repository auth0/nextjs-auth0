import { cookies } from 'next/headers';
import type { CookieSerializeOptions } from 'cookie';
import { Auth0ResponseCookies } from '../auth0-session/http';

let warned = false;

export default class Auth0NextResponseCookies extends Auth0ResponseCookies {
  public constructor() {
    super();
  }

  public setCookie(name: string, value: string, options?: CookieSerializeOptions) {
    const cookieSetter = cookies();
    try {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore see: https://github.com/vercel/next.js/pull/50052
      cookieSetter.set({ ...options, name, value });
      /* c8 ignore next 6 */
    } catch (_) {
      if (process.env.NODE_ENV === 'development' && !warned) {
        console.warn(
          'nextjs-auth0 is attempting to set cookies from a server component,' +
            'see https://github.com/auth0/nextjs-auth0/tree/beta#important-limitations-of-the-app-directory'
        );
        warned = true;
      }
    }
  }

  public clearCookie(name: string, options?: CookieSerializeOptions) {
    const cookieSetter = cookies();
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore see: https://github.com/vercel/next.js/pull/50052
    cookieSetter.delete({ ...options, name, value: '' });
  }
}
