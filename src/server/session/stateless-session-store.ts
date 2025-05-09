import type { JWTPayload } from "jose";

import { ConnectionTokenSet, CookieOptions, SessionData } from "../../types";
import * as cookies from "../cookies";
import {
  AbstractSessionStore,
  SessionCookieOptions
} from "./abstract-session-store";
import {
  LEGACY_COOKIE_NAME,
  LegacySessionPayload,
  normalizeStatelessSession
} from "./normalize-session";

interface StatelessSessionStoreOptions {
  secret: string;

  rolling?: boolean; // defaults to true
  absoluteDuration?: number; // defaults to 3 days
  inactivityDuration?: number; // defaults to 1 day

  cookieOptions?: SessionCookieOptions;
}

export class StatelessSessionStore extends AbstractSessionStore {
  connectionTokenSetsCookieName = "__FC";

  constructor({
    secret,
    rolling,
    absoluteDuration,
    inactivityDuration,
    cookieOptions
  }: StatelessSessionStoreOptions) {
    super({
      secret,
      rolling,
      absoluteDuration,
      inactivityDuration,
      cookieOptions
    });
  }

  async get(reqCookies: cookies.RequestCookies) {
    const cookieValue =
      cookies.getChunkedCookie(this.sessionCookieName, reqCookies) ??
      cookies.getChunkedCookie(LEGACY_COOKIE_NAME, reqCookies);

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

    // As connection access tokens are stored in seperate cookies,
    // we need to get all cookies and only use those that are prefixed with `this.connectionTokenSetsCookieName`
    const connectionTokenSetsCookies = this.getConnectionTokenSetsCookies(
      reqCookies
    );

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
    const expiration = Math.floor(Date.now() / 1000 + maxAge);
    const jwe = await cookies.encrypt(originalSession, this.secret, expiration);
    const cookieValue = jwe.toString();
    const options: CookieOptions = {
      ...this.cookieConfig,
      maxAge
    };

    cookies.setChunkedCookie(
      this.sessionCookieName,
      cookieValue,
      options,
      reqCookies,
      resCookies
    );

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
    cookies.deleteChunkedCookie(LEGACY_COOKIE_NAME, reqCookies, resCookies);
  }

  async delete(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    cookies.deleteChunkedCookie(this.sessionCookieName, reqCookies, resCookies);

    this.getConnectionTokenSetsCookies(reqCookies).forEach((cookie) =>
      resCookies.delete(cookie.name)
    );
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

    if (new TextEncoder().encode(cookieJarSizeTest.toString()).length >= 4096) {
      // if the cookie is the session cookie, log a warning with additional information about the claims and user profile.
      if (cookieName === this.sessionCookieName) {
        console.warn(
          `The ${cookieName} cookie size exceeds 4096 bytes, which may cause issues in some browsers. ` +
            "Consider removing any unnecessary custom claims from the access token or the user profile. " +
            "Alternatively, you can use a stateful session implementation to store the session data in a data store."
        );
      } else {
        console.warn(
          `The ${cookieName} cookie size exceeds 4096 bytes, which may cause issues in some browsers. ` +
            "You can use a stateful session implementation to store the session data in a data store."
        );
      }
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
