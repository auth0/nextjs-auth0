import { NextResponse } from "next/server.js";

/** Marker prefix for all anonymous subjects (design 8.S3: single definition for consistency) */
export const ANONYMOUS_SUBJECT_PREFIX = "anon@";

/** Default cookie name for anonymous session */
export const DEFAULT_ANONYMOUS_SESSION_COOKIE_NAME = "auth0_anon";

/** Metadata size limit in bytes */
export const METADATA_SIZE_LIMIT_BYTES = 1024;

/** Authorization endpoint reserved parameter to strip from caller input */
export const RESERVED_SESSION_TOKEN_PARAM = "session_token";

/**
 * Copy every cookie written on `from` onto `to`, preserving name/value/options.
 * Used by route handlers whose JSON body is only known AFTER token renewal writes
 * cookies: renewal collects cookies in a temp NextResponse, then this moves them onto
 * the final NextResponse.json(...) that is returned to the client (fixation-safe: no
 * request-supplied cookies involved; only SDK-persisted anonymous cookies are moved).
 */
export function transferCookies(from: NextResponse, to: NextResponse): void {
  for (const cookie of from.cookies.getAll()) {
    to.cookies.set(cookie);
  }
}
