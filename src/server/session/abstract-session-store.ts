import type { NextRequest } from "next/server.js";

import type { SessionData, SessionDataStore } from "../../types/index.js";
import {
  CookieOptions,
  ReadonlyRequestCookies,
  RequestCookies,
  ResponseCookies
} from "../cookies/index.js";
import type { BeforeSessionRolledHook, SessionStoreOptions } from "./types.js";

export type {
  BeforeSessionRolledHook,
  SessionConfiguration,
  SessionCookieOptions,
  SessionStoreOptions
} from "./types.js";

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
   * Deletes the backing-store record for the session identified by the request cookies,
   * without needing a response object. Used by IPSIE ceiling enforcement where only
   * reqCookies are available (e.g. getSessionWithDomainCheck).
   *
   * For stateless cookie sessions this is a no-op — the cookie is the session, and
   * clearing it requires response cookies. Ceiling enforcement returns null on every
   * read anyway, so the orphaned cookie is harmless until its natural max-age expires.
   *
   * Subclasses that own a backing store (stateful) SHOULD override this to delete
   * the store record by session ID for hygiene.
   */

  async deleteByReqCookies(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _reqCookies: RequestCookies | ReadonlyRequestCookies
  ): Promise<void> {
    // Default no-op. Stateless stores override to clear the cookie;
    // stateful stores override to delete the backing record.
    // Non-abstract so existing external subclasses are not broken.
  }

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
