import type { JWTPayload } from "jose";

import {
  ConnectionTokenSet,
  CookieOptions,
  SessionData
} from "../../types/index.js";
import * as cookies from "../cookies.js";
import {
  AbstractSessionStore,
  BeforeSessionRolledHook,
  SessionCookieOptions
} from "./abstract-session-store.js";
import {
  LEGACY_COOKIE_NAME,
  LegacySessionPayload,
  normalizeStatelessSession
} from "./normalize-session.js";

// Total encoded session-cookie size (across all `__session` chunks) above which
// we warn. A large session is the main remaining cause of `431 Request Header
// Fields Too Large`, since — unlike transaction cookies — the session is not
// evicted. 4096 bytes is a conservative threshold: at this size the session
// alone is large, and combined with transaction, connection-token, and
// application cookies the total `Cookie` header can exceed typical 8 KB proxy
// limits. Firing early gives developers a clear "trim your claims or go
// stateful" signal before requests start failing.
const SESSION_COOKIE_SIZE_WARN_BYTES = 4096;

// Under rolling sessions, set() runs on ~every authenticated request, so a
// legitimately large-but-working session would otherwise log the size warning
// on every request. Emit it once per process to keep the diagnostic without
// spamming logs.
let sessionSizeWarningEmitted = false;

interface StatelessSessionStoreOptions {
  secret: string;

  rolling?: boolean; // defaults to true
  beforeSessionRolled?: BeforeSessionRolledHook;
  absoluteDuration?: number; // defaults to 3 days
  inactivityDuration?: number; // defaults to 1 day

  cookieOptions?: SessionCookieOptions;
}

export class StatelessSessionStore extends AbstractSessionStore {
  connectionTokenSetsCookieName = "__FC";

  constructor({
    secret,
    rolling,
    beforeSessionRolled,
    absoluteDuration,
    inactivityDuration,
    cookieOptions
  }: StatelessSessionStoreOptions) {
    super({
      secret,
      rolling,
      beforeSessionRolled,
      absoluteDuration,
      inactivityDuration,
      cookieOptions
    });
  }

  async get(reqCookies: cookies.RequestCookies) {
    const cookieValue =
      cookies.getChunkedCookie(this.sessionCookieName, reqCookies) ??
      cookies.getChunkedCookie(LEGACY_COOKIE_NAME, reqCookies, true);

    if (!cookieValue) {
      return null;
    }

    const originalSession = await cookies.decrypt<
      SessionData | LegacySessionPayload
    >(cookieValue, this.secret);

    if (!originalSession) {
      return null;
    }

    const normalizedStatelessSession =
      normalizeStatelessSession(originalSession);

    // As connection access tokens are stored in separate cookies,
    // we need to get all cookies and only use those that are prefixed with `this.connectionTokenSetsCookieName`
    const connectionTokenSetsCookies =
      this.getConnectionTokenSetsCookies(reqCookies);

    const connectionTokenSets = [];
    for (const cookie of connectionTokenSetsCookies) {
      const decryptedCookie = await cookies.decrypt<ConnectionTokenSet>(
        cookie.value,
        this.secret
      );

      if (decryptedCookie) {
        connectionTokenSets.push(decryptedCookie.payload);
      }
    }

    return {
      ...normalizedStatelessSession,
      // Ensure that when there are no connection token sets, we omit the property.
      ...(connectionTokenSets.length
        ? {
            connectionTokenSets
          }
        : {})
    };
  }

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header.
   */
  async set(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData
  ) {
    const { connectionTokenSets, ...originalSession } = session;
    const maxAge = this.calculateMaxAge(session.internal.createdAt);
    // Use consistent timestamp to avoid race condition - align with calculateMaxAge logic
    const now = this.epoch();
    const expiration = now + maxAge;
    const jwe = await cookies.encrypt(originalSession, this.secret, expiration);
    const cookieValue = jwe.toString();
    const options: CookieOptions = {
      ...this.cookieConfig,
      maxAge
    };

    // Warn when the session cookie is large. This is the main remaining cause of
    // 431 errors: the session (unlike transaction cookies) is never evicted, so
    // an oversized session can overflow the request-header limit on its own.
    // setChunkedCookie returns the total bytes of the chunk(s) it wrote, so no
    // separate re-scan of resCookies is needed.
    const sessionCookieBytes = cookies.setChunkedCookie(
      this.sessionCookieName,
      cookieValue,
      options,
      reqCookies,
      resCookies
    );

    if (
      sessionCookieBytes >= SESSION_COOKIE_SIZE_WARN_BYTES &&
      !sessionSizeWarningEmitted
    ) {
      sessionSizeWarningEmitted = true;
      console.warn(
        `The ${this.sessionCookieName} cookie size is ${sessionCookieBytes} bytes, which may ` +
          "exceed request header size limits and cause 431 Request Header Fields Too Large errors " +
          "on some servers, proxies, or CDNs. Consider removing unnecessary custom claims from the " +
          "access token or the user profile, or use a stateful session implementation to store the " +
          "session data in a data store."
      );
    }

    // Store connection access tokens, each in its own cookie
    if (connectionTokenSets?.length) {
      await Promise.all(
        connectionTokenSets.map((connectionTokenSet, index) =>
          this.storeInCookie(
            reqCookies,
            resCookies,
            connectionTokenSet,
            `${this.connectionTokenSetsCookieName}_${index}`,
            maxAge
          )
        )
      );
    }

    // Any existing v3 cookie can be deleted as soon as we have set a v4 cookie.
    // In stateless sessions, we do have to ensure we delete all chunks.
    // Only delete legacy cookies if they actually exist in the request.
    if (cookies.getChunkedCookie(LEGACY_COOKIE_NAME, reqCookies, true)) {
      cookies.deleteChunkedCookie(
        LEGACY_COOKIE_NAME,
        reqCookies,
        resCookies,
        true,
        {
          domain: this.cookieConfig.domain,
          path: this.cookieConfig.path,
          secure: this.cookieConfig.secure,
          sameSite: this.cookieConfig.sameSite,
          httpOnly: this.cookieConfig.httpOnly
        }
      );
    }
  }

  async delete(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    const deleteOptions = {
      domain: this.cookieConfig.domain,
      path: this.cookieConfig.path,
      secure: this.cookieConfig.secure,
      sameSite: this.cookieConfig.sameSite,
      httpOnly: this.cookieConfig.httpOnly
    };

    cookies.deleteChunkedCookie(
      this.sessionCookieName,
      reqCookies,
      resCookies,
      false,
      deleteOptions
    );

    // delete any existing v3 legacy cookies
    if (cookies.getChunkedCookie(LEGACY_COOKIE_NAME, reqCookies, true)) {
      cookies.deleteChunkedCookie(
        LEGACY_COOKIE_NAME,
        reqCookies,
        resCookies,
        true,
        deleteOptions
      );
    }

    this.getConnectionTokenSetsCookies(reqCookies).forEach((cookie) =>
      cookies.deleteCookie(resCookies, cookie.name, deleteOptions)
    );
  }

  override async deleteByReqCookies(): Promise<void> {
    // Stateless sessions are stored in the cookie itself — clearing requires
    // response cookies, which are unavailable here. The ceiling check returns
    // null on every read, so the orphaned cookie is harmless.
  }

  private async storeInCookie(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: JWTPayload,
    cookieName: string,
    maxAge: number
  ) {
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const jwe = await cookies.encrypt(session, this.secret, expiration);

    const cookieValue = jwe.toString();

    resCookies.set(cookieName, jwe.toString(), {
      ...this.cookieConfig,
      maxAge
    });
    // to enable read-after-write in the same request for middleware
    reqCookies.set(cookieName, cookieValue);

    // check if the session cookie size exceeds 4096 bytes, and if so, log a warning
    const cookieJarSizeTest = new cookies.ResponseCookies(new Headers());
    cookieJarSizeTest.set(cookieName, cookieValue, {
      ...this.cookieConfig,
      maxAge
    });

    // storeInCookie only ever writes connection-token (`__FC_*`) cookies — the
    // session cookie is written (and size-checked) separately in set(). Warn if
    // an individual connection-token cookie is large enough to risk browser or
    // header limits.
    if (new TextEncoder().encode(cookieJarSizeTest.toString()).length >= 4096) {
      console.warn(
        `The ${cookieName} cookie size exceeds 4096 bytes, which may cause issues in some browsers. ` +
          "You can use a stateful session implementation to store the session data in a data store."
      );
    }
  }

  private getConnectionTokenSetsCookies(
    cookies: cookies.RequestCookies | cookies.ResponseCookies
  ) {
    return cookies
      .getAll()
      .filter((cookie) =>
        cookie.name.startsWith(this.connectionTokenSetsCookieName)
      );
  }
}
