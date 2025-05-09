import { SessionData, SessionDataStore } from "../../types";
import * as cookies from "../cookies";
import {
  AbstractSessionStore,
  SessionCookieOptions
} from "./abstract-session-store";
import {
  LEGACY_COOKIE_NAME,
  normalizeStatefulSession
} from "./normalize-session";

// the value of the stateful session cookie containing a unique session ID to identify
// the current session
interface SessionCookieValue {
  id: string;
}

interface StatefulSessionStoreOptions {
  secret: string;

  rolling?: boolean; // defaults to true
  absoluteDuration?: number; // defaults to 3 days
  inactivityDuration?: number; // defaults to 1 day

  store: SessionDataStore;

  cookieOptions?: SessionCookieOptions;
}

const generateId = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

export class StatefulSessionStore extends AbstractSessionStore {
  public store: SessionDataStore;

  constructor({
    secret,
    store,
    rolling,
    absoluteDuration,
    inactivityDuration,
    cookieOptions
  }: StatefulSessionStoreOptions) {
    super({
      secret,
      rolling,
      absoluteDuration,
      inactivityDuration,
      cookieOptions
    });

    this.store = store;
  }

  async get(reqCookies: cookies.RequestCookies) {
    const cookie =
      reqCookies.get(this.sessionCookieName) ||
      reqCookies.get(LEGACY_COOKIE_NAME);

    if (!cookie || !cookie.value) {
      return null;
    }

    // we attempt to extract the session ID by decrypting the cookie value (assuming it's a JWE, v4+) first
    // if that fails, we attempt to verify the cookie value as a signed cookie (legacy, v3-)
    // if both fail, we return null
    // this ensures that v3 sessions are respected and can be transparently rolled over to v4+ sessions
    let sessionId: string | null = null;
    try {
      const sessionCookie = await cookies.decrypt<SessionCookieValue>(
        cookie.value,
        this.secret
      );

      if (sessionCookie === null) {
        return null;
      }

      sessionId = sessionCookie.payload.id;
    } catch (e: any) {
      // the session cookie could not be decrypted, try to verify if it's a legacy session
      if (e.code === "ERR_JWE_INVALID") {
        const legacySessionId = await cookies.verifySigned(
          cookie.name,
          cookie.value,
          this.secret
        );

        if (!legacySessionId) {
          return null;
        }

        sessionId = legacySessionId;
      }
    }

    if (!sessionId) {
      return null;
    }

    const session = await this.store.get(sessionId);

    if (!session) {
      return null;
    }

    return normalizeStatefulSession(session);
  }

  async set(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData,
    isNew: boolean = false
  ) {
    // check if a session already exists. If so, maintain the existing session ID
    let sessionId = null;
    const cookieValue = reqCookies.get(this.sessionCookieName)?.value;
    if (cookieValue) {
      const sessionCookie =
        await cookies.decrypt<SessionCookieValue>(cookieValue, this.secret);

      if (sessionCookie) {
        sessionId = sessionCookie.payload.id;
      }
    }

    // if this is a new session created by a new login we need to remove the old session
    // from the store and regenerate the session ID to prevent session fixation.
    if (sessionId && isNew) {
      await this.store.delete(sessionId);
      sessionId = generateId();
    }

    if (!sessionId) {
      sessionId = generateId();
    }

    const maxAge = this.calculateMaxAge(session.internal.createdAt);
    const expiration = Date.now() / 1000 + maxAge;
    const jwe = await cookies.encrypt(
      {
        id: sessionId
      },
      this.secret,
      expiration
    );

    resCookies.set(this.sessionCookieName, jwe.toString(), {
      ...this.cookieConfig,
      maxAge
    });
    await this.store.set(sessionId, session);

    // to enable read-after-write in the same request for middleware
    reqCookies.set(this.sessionCookieName, jwe.toString());

    // Any existing v3 cookie can also be deleted once we have set a v4 cookie.
    // In stateful sessions, we do not have to worry about chunking.
    if (reqCookies.has(LEGACY_COOKIE_NAME)) {
      resCookies.delete(LEGACY_COOKIE_NAME);
    }
  }

  async delete(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    const cookieValue = reqCookies.get(this.sessionCookieName)?.value;
    await resCookies.delete(this.sessionCookieName);

    if (!cookieValue) {
      return;
    }

    const session = await cookies.decrypt<SessionCookieValue>(
      cookieValue,
      this.secret
    );

    if (session) {
      await this.store.delete(session.payload.id);
    }
  }
}
