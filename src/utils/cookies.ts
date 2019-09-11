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
 * Serialize a cookie to a string.
 * @param cookie The cookie to serialize
 */
function serializeCookie(cookie: ICookie): string {
  return serialize(cookie.name, cookie.value, {
    maxAge: cookie.maxAge,
    expires: new Date(Date.now() + cookie.maxAge * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    path: cookie.path
  });
}

/**
 * Set one or more cookies.
 * @param res The HTTP response on which the cookie will be set.
 */
export function setCookies(res: ServerResponse, cookies: Array<ICookie>): void {
  res.setHeader('Set-Cookie', cookies.map(serializeCookie));
}

/**
 * Set one or more cookies.
 * @param res The HTTP response on which the cookie will be set.
 */
export function setCookie(res: ServerResponse, cookie: ICookie): void {
  res.setHeader('Set-Cookie', serializeCookie(cookie));
}
