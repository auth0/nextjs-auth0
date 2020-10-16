import { serialize } from 'cookie'

/**
 * This sets `cookie` on `res` object
 */
const cookie = (res, name, value, options = {}) => {
  const stringValue =
      typeof value === 'object' ? 'j:' + JSON.stringify(value) : String(value)

  if ('maxAge' in options) {
    options.expires = new Date(Date.now() + options.maxAge)
    options.maxAge /= 1000
  }

  const headers = res.getHeader('Set-Cookie') || [];
  headers.push(serialize(name, String(stringValue), options));

  res.setHeader('Set-Cookie', headers);
}

/**
 * Adds `cookie` function on `res.cookie` to set cookies for response
 */
const cookies = (req, res) => {
  res.cookie = (name, value, options) => cookie(res, name, value, options);
  res.clearCookie = (name, options) => cookie(res, name, '', { ...options, expires: 0, maxAge: 0 });
}

export default cookies
