import type { NextRequest } from "next/server.js";

import type { SessionDataStore } from "../../types/index.js";
import type { LegacySession } from "./normalize-session.js";

/**
 * A predicate function that decides whether the session expiry should be extended
 * on a pass-through request (one that does not match an auth route). Return `false`
 * to skip the expiry bump for that request. May be synchronous or asynchronous.
 *
 * Only consulted when `rolling` is enabled. Only applies to the middleware's passive
 * session-touch path — writes triggered by token refresh, `updateSession`, or
 * authentication flows always proceed regardless of this hook, because the session
 * data itself changed.
 *
 * If the hook throws or rejects, the SDK fails open and rolls the session as usual
 * (a warning is logged).
 *
 * Default: `undefined` (the session is always rolled).
 */
export type BeforeSessionRolledHook = (
  req: NextRequest
) => boolean | Promise<boolean>;

export interface SessionCookieOptions {
  /**
   * The name of the session cookie.
   *
   * Default: `__session`.
   */
  name?: string;
  /**
   * The sameSite attribute of the session cookie.
   *
   * Default: `lax`.
   */
  sameSite?: "strict" | "lax" | "none";
  /**
   * The secure attribute of the session cookie.
   *
   * Default: depends on the protocol of the application's base URL. If the protocol is `https`, then `true`, otherwise `false`.
   */
  secure?: boolean;
  /**
   * The path attribute of the session cookie. Will be set to '/' by default.
   */
  path?: string;
  /**
   * Specifies the value for the {@link https://tools.ietf.org/html/rfc6265#section-5.2.3 | Domain Set-Cookie attribute}. By default, no
   * domain is set, and most clients will consider the cookie to apply to only
   * the current domain.
   */
  domain?: string;
  /**
   * The transient attribute of the session cookie. When true, the cookie will not persist beyond the current session.
   */
  transient?: boolean;
}

export interface SessionConfiguration {
  /**
   * A boolean indicating whether rolling sessions should be used or not.
   *
   * When enabled, the session will continue to be extended as long as it is used within the inactivity duration.
   * Once the upper bound, set via the `absoluteDuration`, has been reached, the session will no longer be extended.
   *
   * Default: `true`.
   */
  rolling?: boolean;
  /**
   * A predicate function that decides whether the session should be rolled for an
   * incoming request. Return `false` to skip rolling the session for that request.
   * May be synchronous or asynchronous.
   *
   * Allows you to filter and optimize requests to the session store. Only consulted
   * when `rolling` is enabled. If the hook throws or rejects, the SDK fails open and
   * rolls the session as usual.
   *
   * Default: `undefined` (the session is always rolled).
   */
  beforeSessionRolled?: BeforeSessionRolledHook;
  /**
   * The absolute duration after which the session will expire. The value must be specified in seconds.
   *
   * Once the absolute duration has been reached, the session will no longer be extended.
   *
   * Default: 3 days.
   */
  absoluteDuration?: number;
  /**
   * The duration of inactivity after which the session will expire. The value must be specified in seconds.
   *
   * The session will be extended as long as it was active before the inactivity duration has been reached.
   *
   * Default: 1 day.
   */
  inactivityDuration?: number;

  /**
   * The options for the session cookie.
   */
  cookie?: SessionCookieOptions;
}

export interface SessionStoreOptions extends SessionConfiguration {
  secret: string;
  store?: SessionDataStore;

  cookieOptions?: SessionCookieOptions;
}

/**
 * Key-value store for the user's claims.
 */
export interface LegacyClaims {
  [key: string]: any;
}

/**
 * The legacy headers of the session.
 */
export interface LegacyHeaders {
  /**
   * Timestamp (in secs) when the session was created.
   */
  iat: number;
  /**
   * Timestamp (in secs) when the session was last touched.
   */
  uat: number;
  /**
   * Timestamp (in secs) when the session expires.
   */
  exp: number;
}

export interface LegacySessionPayload {
  /**
   * The session header.
   */
  header: LegacyHeaders;

  /**
   * The session data.
   */
  data: LegacySession;
}

// the value of the stateful session cookie containing a unique session ID to identify
// the current session
export interface SessionCookieValue {
  id: string;
}

export interface StatefulSessionStoreOptions {
  secret: string;

  rolling?: boolean; // defaults to true
  beforeSessionRolled?: BeforeSessionRolledHook;
  absoluteDuration?: number; // defaults to 3 days
  inactivityDuration?: number; // defaults to 1 day

  store: SessionDataStore;

  cookieOptions?: SessionCookieOptions;
}

export interface StatelessSessionStoreOptions {
  secret: string;

  rolling?: boolean; // defaults to true
  beforeSessionRolled?: BeforeSessionRolledHook;
  absoluteDuration?: number; // defaults to 3 days
  inactivityDuration?: number; // defaults to 1 day

  cookieOptions?: SessionCookieOptions;
}

/**
 * Input type for expires-at values that may come from various sources.
 * Supports number (epoch seconds), string (parseable number), null, or undefined.
 */
export type ExpiresAtInput = number | string | null | undefined;
