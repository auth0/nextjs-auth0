import type { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";

import type { ReadonlyRequestCookies } from "../types/cookies.js";

/**
 * Per-request cookie access handed to the engine as its store options.
 *
 * In a Server Action both fields are the same `cookies()` store from `next/headers`.
 */
export interface CookieContext {
  reqCookies: RequestCookies | ReadonlyRequestCookies;
  /**
   * Where writes and deletes go. When absent, writes and deletes are skipped (read-only call).
   */
  resCookies?: ResponseCookies | ReadonlyRequestCookies;
  /**
   * When `true`, a write that throws (a Server Component cannot set cookies) is ignored and
   * `writeFailed` is set instead, so the caller can still return its result.
   */
  ignoreWriteErrors?: boolean;
  /**
   * Set by the cookie handler when a write was ignored because of `ignoreWriteErrors`.
   */
  writeFailed?: boolean;
}
