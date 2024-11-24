import { SessionData } from "../../types"
import * as cookies from "../cookies"
import { AbstractSessionStore } from "./abstract-session-store"

interface StatelessSessionStoreOptions {
  secret: string

  rolling?: boolean // defaults to true
  absoluteDuration?: number // defaults to 30 days
  inactivityDuration?: number // defaults to 7 days
}

export class StatelessSessionStore extends AbstractSessionStore {
  constructor({
    secret,
    rolling,
    absoluteDuration,
    inactivityDuration,
  }: StatelessSessionStoreOptions) {
    super({
      secret,
      rolling,
      absoluteDuration,
      inactivityDuration,
    })
  }

  async get(reqCookies: cookies.RequestCookies) {
    const cookieValue = reqCookies.get(this.SESSION_COOKIE_NAME)?.value

    if (!cookieValue) {
      return null
    }

    return cookies.decrypt<SessionData>(cookieValue, this.secret)
  }

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header.
   */
  async set(
    _reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData,
    _isNew?: boolean
  ) {
    const jwe = await cookies.encrypt(session, this.secret)
    const maxAge = this.calculateMaxAge(session.internal.createdAt)

    resCookies.set(this.SESSION_COOKIE_NAME, jwe.toString(), {
      ...this.cookieConfig,
      maxAge,
    })

    // check if the session cookie size exceeds 4096 bytes, and if so, log a warning
    const cookieJarSizeTest = new cookies.ResponseCookies(new Headers())
    cookieJarSizeTest.set(this.SESSION_COOKIE_NAME, jwe.toString(), {
      ...this.cookieConfig,
      maxAge,
    })
    if (new TextEncoder().encode(cookieJarSizeTest.toString()).length >= 4096) {
      console.warn(
        "The session cookie size exceeds 4096 bytes, which may cause issues in some browsers. " +
          "Consider removing any unnecessary custom claims from the access token or the user profile. " +
          "Alternatively, you can use a stateful session implementation to store the session data in a data store."
      )
    }
  }

  async delete(
    _reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    await resCookies.delete(this.SESSION_COOKIE_NAME)
  }
}
