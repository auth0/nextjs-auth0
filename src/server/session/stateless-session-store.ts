import { CookieOptions, SessionData } from "../../types";
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

    return normalizeStatelessSession(originalSession);
  }

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header.
   */
  async set(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData
  ) {
    const jwe = await cookies.encrypt(session, this.secret);
    const maxAge = this.calculateMaxAge(session.internal.createdAt);
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
  }

  async delete(
    _reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    cookies.deleteChunkedCookie(
      this.sessionCookieName,
      _reqCookies,
      resCookies
    );
  }
}
