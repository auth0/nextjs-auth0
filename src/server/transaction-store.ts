import type * as jose from "jose"

import * as cookies from "./cookies"

const TRANSACTION_COOKIE_PREFIX = "__txn_"

export interface TransactionState extends jose.JWTPayload {
  nonce: string
  codeVerifier: string
  responseType: string
  state: string // the state parameter passed to the authorization server
  returnTo: string // the URL to redirect to after login
  maxAge?: number // the maximum age of the authentication session
}

interface TransactionStoreOptions {
  secret: string
  cookieOptions?: Partial<Pick<cookies.CookieOptions, "secure">>
}

/**
 * TransactionStore is responsible for storing the state required to successfully complete
 * an authentication transaction. The store relies on encrypted, stateless cookies to store
 * the transaction state.
 */
export class TransactionStore {
  private secret: string
  private cookieConfig: cookies.CookieOptions

  constructor({ secret, cookieOptions }: TransactionStoreOptions) {
    this.secret = secret
    this.cookieConfig = {
      httpOnly: true,
      sameSite: "lax", // required to allow the cookie to be sent on the callback request
      secure: cookieOptions?.secure ?? false,
      path: "/",
      maxAge: 60 * 60, // 1 hour in seconds
    }
  }

  /**
   * Returns the name of the cookie used to store the transaction state.
   * The cookie name is derived from the state parameter to prevent collisions
   * between different transactions.
   */
  private getTransactionCookieName(state: string) {
    return `${TRANSACTION_COOKIE_PREFIX}${state}`
  }

  async save(
    resCookies: cookies.ResponseCookies,
    transactionState: TransactionState
  ) {
    const jwe = await cookies.encrypt(transactionState, this.secret)

    if (!transactionState.state) {
      throw new Error("Transaction state is required")
    }

    resCookies.set(
      this.getTransactionCookieName(transactionState.state),
      jwe.toString(),
      this.cookieConfig
    )
  }

  async get(reqCookies: cookies.RequestCookies, state: string) {
    const cookieName = this.getTransactionCookieName(state)
    const cookieValue = reqCookies.get(cookieName)?.value

    if (!cookieValue) {
      return null
    }

    return cookies.decrypt<TransactionState>(cookieValue, this.secret)
  }

  async delete(resCookies: cookies.ResponseCookies, state: string) {
    await resCookies.delete(this.getTransactionCookieName(state))
  }
}
