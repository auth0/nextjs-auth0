import type { NextRequest } from "next/server.js";

import type { SessionData, SessionDataStore } from "../../types/index.js";
import {
  CookieOptions,
  ReadonlyRequestCookies,
  RequestCookies,
  ResponseCookies
} from "../cookies.js";

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
   * Specifies the value for the {@link https://tools.ietf.org/html/rfc6265#section-5.2.3|Domain Set-Cookie attribute}. By default, no
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

const SESSION_COOKIE_NAME = "__session";

export abstract class AbstractSessionStore {
  public secret: string;
  public sessionCookieName: string;

  protected rolling: boolean;
  private beforeSessionRolled?: BeforeSessionRolledHook;
  private absoluteDuration: number;
  private inactivityDuration: number;

  public store?: SessionDataStore;

  public cookieConfig: CookieOptions;

  constructor({
    secret,

    rolling = true,
    beforeSessionRolled,
    absoluteDuration = 60 * 60 * 24 * 3, // 3 days in seconds
    inactivityDuration = 60 * 60 * 24 * 1, // 1 day in seconds
    store,

    cookieOptions
  }: SessionStoreOptions) {
    this.secret = secret;

    this.rolling = rolling;
    this.beforeSessionRolled = beforeSessionRolled;
    this.absoluteDuration = absoluteDuration;
    this.inactivityDuration = inactivityDuration;
    this.store = store;

    this.sessionCookieName = cookieOptions?.name ?? SESSION_COOKIE_NAME;
    this.cookieConfig = {
      httpOnly: true,
      sameSite: cookieOptions?.sameSite ?? "lax",
      secure: cookieOptions?.secure ?? false,
      path: cookieOptions?.path ?? "/",
      domain: cookieOptions?.domain,
      transient: cookieOptions?.transient
    };
  }

  abstract get(
    reqCookies: RequestCookies | ReadonlyRequestCookies
  ): Promise<SessionData | null>;

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header. If the `iat` property
   * is present on the session, then it will be used to compute the `maxAge` cookie value.
   */
  abstract set(
    reqCookies: RequestCookies | ReadonlyRequestCookies,
    resCookies: ResponseCookies,
    session: SessionData,
    isNew?: boolean
  ): Promise<void>;

  abstract delete(
    reqCookies: RequestCookies | ReadonlyRequestCookies,
    resCookies: ResponseCookies
  ): Promise<void>;

  /**
   * isRolling returns true if rolling sessions are enabled.
   */
  get isRolling(): boolean {
    return this.rolling;
  }

  async shouldRollSession(req: NextRequest): Promise<boolean> {
    if (!this.rolling) {
      return false;
    }

    if (!this.beforeSessionRolled) {
      return true;
    }

    try {
      return await this.beforeSessionRolled(req);
    } catch (e) {
      console.warn(
        "The beforeSessionRolled hook threw an error. Defaulting to rolling the session.",
        e
      );
      return true;
    }
  }

  /**
   * epoch returns the time since unix epoch in seconds.
   */
  epoch() {
    return (Date.now() / 1000) | 0;
  }

  /**
   * calculateMaxAge calculates the max age of the session based on createdAt and the rolling and absolute durations.
   */
  calculateMaxAge(createdAt: number) {
    if (!this.rolling) {
      return this.absoluteDuration;
    }

    const updatedAt = this.epoch();
    const expiresAt = Math.min(
      updatedAt + this.inactivityDuration,
      createdAt + this.absoluteDuration
    );
    // Fix race condition: use the same updatedAt timestamp for consistency
    const maxAge = expiresAt - updatedAt;

    return maxAge > 0 ? maxAge : 0;
  }
}
