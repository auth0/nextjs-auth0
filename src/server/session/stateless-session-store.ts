import { SessionData } from "../../types";
import * as cookies from "../cookies";
import {
  AbstractSessionStore,
  SessionCookieOptions
} from "./abstract-session-store";

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
    const cookieValue = reqCookies.get(this.sessionCookieName)?.value;

    if (!cookieValue) {
      return null;
    }

    return cookies.decrypt<SessionData>(cookieValue, this.secret);
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

    resCookies.set(this.sessionCookieName, jwe.toString(), {
      ...this.cookieConfig,
      maxAge
    });
    // to enable read-after-write in the same request for middleware
    reqCookies.set(this.sessionCookieName, cookieValue);

    // check if the session cookie size exceeds 4096 bytes, and if so, log a warning
    const cookieJarSizeTest = new cookies.ResponseCookies(new Headers());
    cookieJarSizeTest.set(this.sessionCookieName, cookieValue, {
      ...this.cookieConfig,
      maxAge
    });
    if (new TextEncoder().encode(cookieJarSizeTest.toString()).length >= 4096) {
      console.warn(
        "The session cookie size exceeds 4096 bytes, which may cause issues in some browsers. " +
          "Consider removing any unnecessary custom claims from the access token or the user profile. " +
          "Alternatively, you can use a stateful session implementation to store the session data in a data store."
      );
    }
  }

  async delete(
    _reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    await resCookies.delete(this.sessionCookieName);
  }
}
