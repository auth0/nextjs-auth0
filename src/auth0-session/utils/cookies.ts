import { IncomingMessage, ServerResponse } from 'http';
import { CookieSerializeOptions, parse, serialize } from 'cookie';

export const getAll = (req: IncomingMessage) => {
  return parse(req?.headers?.cookie || '');
};

export const get = (req: IncomingMessage, name: string) => {
  const cookies = getAll(req);
  return cookies[name];
};

export const set = (res: ServerResponse, name: string, value: string, options: CookieSerializeOptions = {}) => {
  const strCookie = serialize(name, value, options);

  let previousCookies = res.getHeader('Set-Cookie') || [];
  if (!Array.isArray(previousCookies)) {
    previousCookies = [previousCookies as string];
  }

  res.setHeader('Set-Cookie', [strCookie, ...previousCookies]);
};

export const clear = (res: ServerResponse, name: string, options: CookieSerializeOptions = {}) => {
  set(res, name, '', { ...options, maxAge: 0 });
};
