"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const cookie_1 = require("cookie");
/**
 * Parses the cookies from an API Route or from Pages and returns a key/value object containing all the cookies.
 * @param req Incoming HTTP request.
 */
function parseCookies(req) {
    const { cookies } = req;
    // For API Routes we don't need to parse the cookies.
    if (cookies) {
        return cookies;
    }
    // For pages we still need to parse the cookies.
    const cookie = req && req.headers && req.headers.cookie;
    return cookie_1.parse(cookie || '');
}
exports.parseCookies = parseCookies;
/**
 * Serialize a cookie to a string.
 * @param cookie The cookie to serialize
 */
function serializeCookie(cookie) {
    return cookie_1.serialize(cookie.name, cookie.value, {
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
function setCookies(res, cookies) {
    res.setHeader('Set-Cookie', cookies.map(serializeCookie));
}
exports.setCookies = setCookies;
/**
 * Set one or more cookies.
 * @param res The HTTP response on which the cookie will be set.
 */
function setCookie(res, cookie) {
    res.setHeader('Set-Cookie', serializeCookie(cookie));
}
exports.setCookie = setCookie;
//# sourceMappingURL=cookies.js.map