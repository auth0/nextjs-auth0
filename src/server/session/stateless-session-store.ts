import { FederatedConnectionTokenSet, SessionData } from "../../types";
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
  federatedConnectionTokenSetsCookieName = '__federated_connections'

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

    const originalSession = await cookies.decrypt<SessionData>(
      cookieValue,
      this.secret
    );

    // As federated connection access tokens are stored in seperate cookies,
    // we need to get all cookies and only use those that are prefixed with `this.federatedConnectionTokenSetsCookieName`
    const federatedConnectionTokenSets = await Promise.all(
      this.getFederatedConnectionTokenSetsCookies(reqCookies).map(
        (fcatCookie) =>
          cookies.decrypt<FederatedConnectionTokenSet>(
            fcatCookie.value,
            this.secret
          )
      )
    )

    return {
      ...originalSession,
      federatedConnectionTokenSets,
    }
  }

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header.
   */
  async set(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData
  ) {

    const { federatedConnectionTokenSets, ...originalSession } = session
    const maxAge = this.calculateMaxAge(session.internal.createdAt)

    await this.storeInCookie(
      reqCookies,
      resCookies,
      originalSession,
      this.sessionCookieName,
      maxAge
    );

    // Store federated connection access tokens, each in its own cookie
    if (federatedConnectionTokenSets?.length) {
      await Promise.all(
        federatedConnectionTokenSets.map((federatedConnectionTokenSet, index) =>
          this.storeInCookie(
            reqCookies,
            resCookies,
            federatedConnectionTokenSet,
            `${this.federatedConnectionTokenSetsCookieName}_${index}`,
            maxAge
          )
        )
      )
    }
  }

  async delete(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    resCookies.delete(this.sessionCookieName);
    this.getFederatedConnectionTokenSetsCookies(reqCookies)
      .forEach(cookie => resCookies.delete(cookie.name));
    
  }

  private async storeInCookie(reqCookies: cookies.RequestCookies, resCookies: cookies.ResponseCookies, session: JWTPayload, sessionCookieName: string, maxAge: number) {
    const jwe = await cookies.encrypt(session, this.secret);
    
    const cookieValue = jwe.toString();

    resCookies.set(sessionCookieName, jwe.toString(), {
      ...this.cookieConfig,
      maxAge
    });
    // to enable read-after-write in the same request for middleware
    reqCookies.set(sessionCookieName, cookieValue);

    // check if the session cookie size exceeds 4096 bytes, and if so, log a warning
    const cookieJarSizeTest = new cookies.ResponseCookies(new Headers());
    cookieJarSizeTest.set(sessionCookieName, cookieValue, {
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

  private getFederatedConnectionTokenSetsCookies(cookies: cookies.RequestCookies | cookies.ResponseCookies) {
    return cookies
      .getAll()
      .filter(cookie => cookie.name.startsWith(this.federatedConnectionTokenSetsCookieName));
  }
}