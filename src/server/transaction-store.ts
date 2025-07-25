import type * as jose from "jose";

import * as cookies from "./cookies.js";

const TRANSACTION_COOKIE_PREFIX = "__txn_";

export interface TransactionState extends jose.JWTPayload {
  nonce: string;
  codeVerifier: string;
  responseType: string;
  state: string; // the state parameter passed to the authorization server
  returnTo: string; // the URL to redirect to after login
  maxAge?: number; // the maximum age of the authentication session
}

export interface TransactionCookieOptions {
  /**
   * The prefix of the cookie used to store the transaction state.
   *
   * Default: `__txn_{state}`.
   */
  prefix?: string;
  /**
   * The sameSite attribute of the transaction cookie.
   *
   * Default: `lax`.
   */
  sameSite?: "strict" | "lax" | "none";
  /**
   * The secure attribute of the transaction cookie.
   *
   * Default: depends on the protocol of the application's base URL. If the protocol is `https`, then `true`, otherwise `false`.
   */
  secure?: boolean;
  /**
   * The path attribute of the transaction cookie. Will be set to '/' by default.
   */
  path?: string;
}

export interface TransactionStoreOptions {
  secret: string;
  cookieOptions?: TransactionCookieOptions;
  /**
   * Controls whether multiple parallel login transactions are allowed.
   * When false, only one transaction cookie is maintained at a time.
   * When true (default), multiple transaction cookies can coexist for multi-tab support.
   *
   * @default true
   */
  enableParallelTransactions?: boolean;
}

/**
 * TransactionStore is responsible for storing the state required to successfully complete
 * an authentication transaction. The store relies on encrypted, stateless cookies to store
 * the transaction state.
 */
export class TransactionStore {
  private secret: string;
  private transactionCookiePrefix: string;
  private cookieConfig: cookies.CookieOptions;
  private readonly enableParallelTransactions: boolean;

  constructor({
    secret,
    cookieOptions,
    enableParallelTransactions
  }: TransactionStoreOptions) {
    this.secret = secret;
    this.transactionCookiePrefix =
      cookieOptions?.prefix ?? TRANSACTION_COOKIE_PREFIX;
    this.cookieConfig = {
      httpOnly: true,
      sameSite: cookieOptions?.sameSite ?? "lax", // required to allow the cookie to be sent on the callback request
      secure: cookieOptions?.secure ?? false,
      path: cookieOptions?.path ?? "/",
      maxAge: 60 * 60 // 1 hour in seconds
    };
    this.enableParallelTransactions = enableParallelTransactions ?? true;
  }

  /**
   * Returns the name of the cookie used to store the transaction state.
   * The cookie name is derived from the state parameter to prevent collisions
   * between different transactions.
   */
  private getTransactionCookieName(state: string) {
    return this.enableParallelTransactions
      ? `${this.transactionCookiePrefix}${state}`
      : `${this.transactionCookiePrefix}`;
  }

  /**
   * Returns the configured prefix for transaction cookies.
   */
  public getCookiePrefix(): string {
    return this.transactionCookiePrefix;
  }

  /**
   * Saves the transaction state to an encrypted cookie.
   *
   * @param resCookies - The response cookies object to set the transaction cookie on
   * @param transactionState - The transaction state to save
   * @param reqCookies - Optional request cookies to check for existing transactions.
   *                     When provided and `enableParallelTransactions` is false,
   *                     will check for existing transaction cookies. When omitted,
   *                     the existence check is skipped for performance optimization.
   * @throws {Error} When transaction state is missing required state parameter
   */
  async save(
    resCookies: cookies.ResponseCookies,
    transactionState: TransactionState,
    reqCookies?: cookies.RequestCookies
  ) {
    const expiration = Math.floor(
      Date.now() / 1000 + this.cookieConfig.maxAge!
    );
    if (!transactionState.state) {
      throw new Error("Transaction state is required");
    }

    // When parallel transactions are disabled, check if a transaction already exists
    if (reqCookies && !this.enableParallelTransactions) {
      const cookieName = this.getTransactionCookieName(transactionState.state);
      const existingCookie = reqCookies.get(cookieName);
      if (existingCookie) {
        console.warn(
          "A transaction is already in progress. Only one transaction is allowed when parallel transactions are disabled."
        );
        return;
      }
    }
    const jwe = await cookies.encrypt(
      transactionState,
      this.secret,
      expiration
    );

    if (!transactionState.state) {
      throw new Error("Transaction state is required");
    }

    resCookies.set(
      this.getTransactionCookieName(transactionState.state),
      jwe.toString(),
      this.cookieConfig
    );
  }

  async get(reqCookies: cookies.RequestCookies, state: string) {
    const cookieName = this.getTransactionCookieName(state);
    const cookieValue = reqCookies.get(cookieName)?.value;

    if (!cookieValue) {
      return null;
    }

    return cookies.decrypt<TransactionState>(cookieValue, this.secret);
  }

  async delete(resCookies: cookies.ResponseCookies, state: string) {
    cookies.deleteCookie(
      resCookies,
      this.getTransactionCookieName(state),
      this.cookieConfig.path
    );
  }

  /**
   * Deletes all transaction cookies based on the configured prefix.
   */
  async deleteAll(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    const txnPrefix = this.getCookiePrefix();
    reqCookies.getAll().forEach((cookie) => {
      if (cookie.name.startsWith(txnPrefix)) {
        cookies.deleteCookie(resCookies, cookie.name, this.cookieConfig.path);
      }
    });
  }
}
