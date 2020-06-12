import { NextApiRequest } from 'next';
import { parse, serialize } from 'cookie';
import { IncomingMessage, ServerResponse } from 'http';

interface ICookies {
  [key: string]: string;
}

interface ICookie {
  /**
   * The name of the cookie.
   */
  name: string;

  /**
   *  The value of the cookie.
   */
  value: string;

  /**
   * The maximum age of the cookie in milliseconds.
   */
  maxAge: number;

  /**
   * The path of the cookie
   */
  path?: string;

  /**
   * The domain of the cookie
   */
  domain?: string;

  /**
   * SameSite configuration for the session cookie.
   */
  sameSite?: boolean | 'lax' | 'strict' | 'none' | undefined;
}

/**
 * Parses the cookies from an API Route or from Pages and returns a key/value object containing all the cookies.
 * @param req Incoming HTTP request.
 */
export function parseCookies(req: IncomingMessage): ICookies {
  const { cookies } = req as NextApiRequest;

  // For API Routes we don't need to parse the cookies.
  if (cookies) {
    return cookies;
  }

  // For pages we still need to parse the cookies.
  const cookie = req && req.headers && req.headers.cookie;
  return parse(cookie || '');
}

/**
 * Based on the environment and the request we know if a secure cookie can be set.
 */
function isSecureEnvironment(req: IncomingMessage): boolean {
  if (!req || !req.headers || !req.headers.host) {
    throw new Error('The "host" request header is not available');
  }

  if (process.env.NODE_ENV !== 'production') {
    return false;
  }

  const host = (req.headers.host.indexOf(':') > -1 && req.headers.host.split(':')[0]) || req.headers.host;
  if (['localhost', '127.0.0.1'].indexOf(host) > -1) {
    return false;
  }

  return true;
}

/**
 * Serialize a cookie to a string.
 * @param cookie The cookie to serialize
 * @param secure Create a secure cookie.
 */
function serializeCookie(cookie: ICookie, secure: boolean): string {
  return serialize(cookie.name, cookie.value, {
    maxAge: cookie.maxAge,
    expires: new Date(Date.now() + cookie.maxAge * 1000),
    httpOnly: true,
    secure,
    path: cookie.path,
    domain: cookie.domain,
    sameSite: cookie.sameSite
  });
}

/**
 * Set one or more cookies.
 * @param res The HTTP response on which the cookie will be set.
 * @returns {void}
 */
export function setCookies(req: IncomingMessage, res: ServerResponse, cookies: Array<ICookie>): void {
  const strCookies = cookies.map((c) => serializeCookie(c, isSecureEnvironment(req)));
  const previousCookies = res.getHeader('Set-Cookie');
  if (previousCookies) {
    if (previousCookies instanceof Array) {
      Array.prototype.push.apply(strCookies, previousCookies);
    } else if (typeof previousCookies === 'string') {
      strCookies.push(previousCookies);
    }
  }
  res.setHeader('Set-Cookie', strCookies);
}

/**
 * Set one or more cookies.
 * @param res The HTTP response on which the cookie will be set.
 * @returns {void}
 */
export function setCookie(req: IncomingMessage, res: ServerResponse, cookie: ICookie): void {
  setCookies(req, res, [cookie]);
}
