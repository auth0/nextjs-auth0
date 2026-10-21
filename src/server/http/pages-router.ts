import type { PagesRouterResponse } from "../types/index.js";

/**
 * Puts the cookies a call wrote onto a Pages Router response. The header is set, not appended, as
 * on `main`: a `set-cookie` the app already put on that response is replaced.
 */
export function setPagesRouterCookies(
  res: PagesRouterResponse,
  written: Headers
): void {
  const values = written.getSetCookie();
  if (values.length > 0) {
    res.setHeader("set-cookie", values);
  }
}

/**
 * Like {@link setPagesRouterCookies}, but appended, as `main`'s `getAccessToken` does: a
 * `set-cookie` the app already put on that response is kept.
 */
export function appendPagesRouterCookies(
  res: PagesRouterResponse,
  written: Headers
): void {
  for (const value of written.getSetCookie()) {
    res.appendHeader("set-cookie", value);
  }
}
