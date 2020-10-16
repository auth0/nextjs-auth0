import { parse, serialize } from 'cookie';
import weakRef from './weak-cache';

export const getAll = (req) => {
  const ref = weakRef(req);
  if (ref.cookies) {
    return ref.cookies;
  }

  const cookies = parse(req?.headers?.cookie || '');
  ref.cookies = cookies;
  return cookies;
};

export const get = (req, name) => {
  const cookies = getAll(req);
  return cookies[name];
};

export const set = (res, name, value, options = {}) => {
  const strCookie = serialize(name, value, options);

  let previousCookies = res.getHeader('Set-Cookie') || [];
  if (!Array.isArray(previousCookies)) {
    previousCookies = [previousCookies];
  }

  res.setHeader('Set-Cookie', [strCookie, ...previousCookies]);
};

export const clear = (res, name, value) => {
  set(res, name, '', { ...options, expires: 0, maxAge: 0 });
};
