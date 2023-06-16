import { Cookies } from '../auth0-session/utils/cookies';
import { NextRequest, NextResponse } from 'next/server';

export default class MiddlewareCookies extends Cookies {
  protected getSetCookieHeader(res: NextResponse): string[] {
    const value = res.headers.get('set-cookie');
    return splitCookiesString(value as string);
  }

  protected setSetCookieHeader(res: NextResponse, cookies: string[]): void {
    res.headers.delete('set-cookie');
    for (const cookie of cookies) {
      res.headers.append('set-cookie', cookie);
    }
  }

  getAll(req: NextRequest): Record<string, string> {
    const { cookies } = req;
    if (typeof cookies.getAll === 'function') {
      return req.cookies.getAll().reduce((memo, { name, value }) => ({ ...memo, [name]: value }), {});
    }
    // Edge cookies before Next 13.0.1 have no `getAll` and extend `Map`.
    const legacyCookies = cookies as unknown as Map<string, string>;
    return Array.from(legacyCookies.keys()).reduce((memo: { [key: string]: string }, key) => {
      memo[key] = legacyCookies.get(key) as string;
      return memo;
    }, {});
  }
}

/* eslint-disable max-len */
/**
 * Handle cookies with commas, eg `foo=; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
 * @source https://github.com/vercel/edge-runtime/blob/90160abc42e6139c41494c5d2e98f09e9a5fa514/packages/cookies/src/response-cookies.ts#L128
 */
export function splitCookiesString(cookiesString: string) {
  if (!cookiesString) return [];
  const cookiesStrings = [];
  let pos = 0;
  let start;
  let ch;
  let lastComma;
  let nextStart;
  let cookiesSeparatorFound;

  function skipWhitespace() {
    while (pos < cookiesString.length && /\s/.test(cookiesString.charAt(pos))) {
      pos += 1;
    }
    return pos < cookiesString.length;
  }

  function notSpecialChar() {
    ch = cookiesString.charAt(pos);

    return ch !== '=' && ch !== ';' && ch !== ',';
  }

  while (pos < cookiesString.length) {
    start = pos;
    cookiesSeparatorFound = false;

    while (skipWhitespace()) {
      ch = cookiesString.charAt(pos);
      if (ch === ',') {
        // ',' is a cookie separator if we have later first '=', not ';' or ','
        lastComma = pos;
        pos += 1;

        skipWhitespace();
        nextStart = pos;

        while (pos < cookiesString.length && notSpecialChar()) {
          pos += 1;
        }

        // currently special character
        if (pos < cookiesString.length && cookiesString.charAt(pos) === '=') {
          // we found cookies separator
          cookiesSeparatorFound = true;
          // pos is inside the next cookie, so back up and return it.
          pos = nextStart;
          cookiesStrings.push(cookiesString.substring(start, lastComma));
          start = pos;
          /* c8 ignore next 5 */
        } else {
          // in param ',' or param separator ';',
          // we continue from that comma
          pos = lastComma + 1;
        }
      } else {
        pos += 1;
      }
    }

    if (!cookiesSeparatorFound || pos >= cookiesString.length) {
      cookiesStrings.push(cookiesString.substring(start, cookiesString.length));
    }
  }

  return cookiesStrings;
}
