import { SessionData } from "../../types"
import * as cookies from "../cookies"
import { SetCookieOptions } from "../cookies"
import {
  deserializeFederatedTokens,
  serializeFederatedTokens,
} from "../federatedConnections/serializer"
import {
  AbstractSessionStore,
  SessionCookieOptions,
} from "./abstract-session-store"

interface StatelessSessionStoreOptions {
  secret: string

  rolling?: boolean // defaults to true
  absoluteDuration?: number // defaults to 3 days
  inactivityDuration?: number // defaults to 1 day

  cookieOptions?: SessionCookieOptions
}

export class StatelessSessionStore extends AbstractSessionStore {
  constructor({
    secret,
    rolling,
    absoluteDuration,
    inactivityDuration,
    cookieOptions,
  }: StatelessSessionStoreOptions) {
    super({
      secret,
      rolling,
      absoluteDuration,
      inactivityDuration,
      cookieOptions,
    })
  }

  /**
   * Retrieves the session data from the request cookies.
   *
   * @param reqCookies - The cookies from the request.
   * @returns A promise that resolves to the session data or null if no session data is found.
   */
  async get(reqCookies: cookies.RequestCookies): Promise<SessionData | null> {
    const session = await cookies.get<SessionData>({
      reqCookies,
      cookieName: this.sessionCookieName,
      secret: this.secret,
    })
    if (session) {
      session.federatedConnectiontMap = (await deserializeFederatedTokens(reqCookies, this.secret)) ?? {}
    }
    return session
  }

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header.
   */
  async set(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData,
    _isNew?: boolean
  ) {
    const { federatedConnectiontMap: fcMap, ...originalSession } = session

    const maxAge = this.calculateMaxAge(originalSession.internal.createdAt)

    const setCookieOptions: SetCookieOptions = {
      reqCookies,
      resCookies,
      payload: originalSession,
      cookieName: this.sessionCookieName,
      maxAge,
      cookieOptions: this.cookieConfig,
      secret: this.secret,
    }

    await cookies.set(setCookieOptions)
    fcMap && (await serializeFederatedTokens(fcMap, setCookieOptions))
  }

  async delete(
    _reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    resCookies.delete(this.sessionCookieName)
  }
}
