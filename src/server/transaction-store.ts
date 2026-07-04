import type * as jose from "jose";

import { RESPONSE_TYPES } from "../types/index.js";
import * as cookies from "./cookies.js";

const TRANSACTION_COOKIE_PREFIX = "__txn_";

// Value prefix for prefetch-created cookies — pure garbage, never leads to a
// real callback. Short maxAge (60s) further limits accumulation window.
const PREFETCH_VALUE_PREFIX = "p:";
const PREFETCH_MAX_AGE = 60; // seconds

export interface TransactionState extends jose.JWTPayload {
  codeVerifier?: string;
  responseType: RESPONSE_TYPES;
  state: string; // the state parameter passed to the authorization server
  returnTo: string; // the URL to redirect to after login
  nonce?: string; // A string value used to associate a client session with an ID Token, and to mitigate replay attacks.  codeVerifier: string;
  maxAge?: number; // the maximum age of the authentication session
  authSession?: string; // the auth session ID for connect accounts
  /**
   * The scope requested for this transaction.
   */
  scope?: string;

  /**
   * The audience used for this transaction.
   */
  audience?: string;

  /**
   * The challenge mode for this transaction.
   * - 'redirect' (default): Standard OAuth redirect flow
   * - 'popup': Popup flow returning via window.postMessage
   */
  challengeMode?: "redirect" | "popup";

  /**
   * The Auth0 domain used for this transaction (MCD mode).
   * Stored to validate that the session is for the same domain.
   * @internal
   */
  originDomain?: string;

  /**
   * The OIDC issuer URL for this transaction (MCD mode).
   * Stored alongside originDomain for validation.
   * @internal
   */
  originIssuer?: string;
}

export interface TransactionCookieOptions {
  /**
   * The prefix of the cookie used to store the transaction state.
   *
   * Default: `__txn_{state}`.
   */
  prefix?: string;
  /**
   * Maximum total byte size of all transaction cookies combined. When the
   * accumulated size meets or exceeds this limit, cookies are evicted before
   * the new one is written using a two-phase strategy:
   *
   * Phase 1 — delete all prefetch cookies (value prefix `p:`). These are
   * provably garbage and never lead to a completed OAuth flow.
   *
   * Phase 2 — if still over threshold after phase 1, evict real login cookies
   * oldest-first by the timestamp encoded in their value prefix (`{ts}:`).
   * Zero crypto decryption happens during eviction.
   *
   * One `__txn_*` JWE is ~450–555 bytes. Default `4096` allows ~7–9 cookies —
   * well under the 8 KB request-header limit most servers enforce.
   *
   * @default 4096
   */
  maxSizeBytes?: number;
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
  /**
   * Specifies the value for the {@link https://tools.ietf.org/html/rfc6265#section-5.2.3|Domain Set-Cookie attribute}. By default, no
   * domain is set, and most clients will consider the cookie to apply to only
   * the current domain.
   */
  domain?: string;
  /**
   * The expiration time for transaction cookies in seconds.
   * If not provided, defaults to 1 hour (3600 seconds).
   *
   * @default 3600
   */
  maxAge?: number;
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
  /**
   * Mirrors the `dangerouslyAllowLoginPrefetch` flag from `Auth0ClientOptions`.
   * Controls the eviction strategy when `maxSizeBytes` is exceeded.
   *
   * @default false
   */
  dangerouslyAllowLoginPrefetch?: boolean;
}

/**
 * TransactionStore is responsible for storing the state required to successfully complete
 * an authentication transaction. The store relies on encrypted, stateless cookies to store
 * the transaction state.
 */
export class TransactionStore {
  private readonly secret: string;
  private readonly transactionCookiePrefix: string;
  private readonly cookieOptions: cookies.CookieOptions;
  private readonly enableParallelTransactions: boolean;
  private readonly maxSizeBytes: number;
  private readonly dangerouslyAllowLoginPrefetch: boolean;

  constructor({
    secret,
    cookieOptions,
    enableParallelTransactions,
    dangerouslyAllowLoginPrefetch
  }: TransactionStoreOptions) {
    this.secret = secret;
    this.transactionCookiePrefix =
      cookieOptions?.prefix ?? TRANSACTION_COOKIE_PREFIX;
    this.cookieOptions = {
      httpOnly: true,
      sameSite: cookieOptions?.sameSite ?? "lax", // required to allow the cookie to be sent on the callback request
      secure: cookieOptions?.secure ?? false,
      path: cookieOptions?.path ?? "/",
      domain: cookieOptions?.domain,
      maxAge: cookieOptions?.maxAge || 60 * 60 // 1 hour in seconds
    };
    this.enableParallelTransactions = enableParallelTransactions ?? true;
    this.maxSizeBytes = cookieOptions?.maxSizeBytes ?? 4096;
    this.dangerouslyAllowLoginPrefetch = dangerouslyAllowLoginPrefetch ?? false;
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
   * @param reqCookies - Optional request cookies. When provided, enables maxSizeBytes
   *                     eviction before writing the new cookie.
   * @param isPrefetch - When true, the cookie value is prefixed with "p:" and gets a
   *                     short maxAge (60s). Prefetch cookies are evicted first during
   *                     eviction and never match a real callback.
   * @throws {Error} When transaction state is missing required state parameter
   */
  async save(
    resCookies: cookies.ResponseCookies,
    transactionState: TransactionState,
    reqCookies?: cookies.RequestCookies,
    isPrefetch?: boolean
  ) {
    if (!transactionState.state) {
      throw new Error("Transaction state is required");
    }

    // Evict accumulated transaction cookies when accumulated size meets the cap.
    // Safety net for abandoned logins and silent prefetches that bypass Fix 1
    // (e.g. router.prefetch(), CDNs that strip sec-fetch-mode).
    if (reqCookies) {
      const existing = reqCookies
        .getAll()
        .filter((c) => c.name.startsWith(this.transactionCookiePrefix));
      const totalBytes = existing.reduce(
        (sum, c) =>
          sum + new TextEncoder().encode(`${c.name}=${c.value}`).length,
        0
      );
      if (totalBytes >= this.maxSizeBytes) {
        // Two-phase eviction — zero crypto decryption.
        // Phase 1: evict all prefetch cookies (value starts with "p:") — always garbage.
        // Phase 2: if still over threshold, evict real login cookies oldest-first
        //          by timestamp encoded in value prefix ("{ts}:").
        const deleteOptions = {
          domain: this.cookieOptions.domain,
          path: this.cookieOptions.path,
          secure: this.cookieOptions.secure,
          sameSite: this.cookieOptions.sameSite,
          httpOnly: this.cookieOptions.httpOnly
        };

        const prefetchCookies = existing.filter((c) =>
          c.value.startsWith(PREFETCH_VALUE_PREFIX)
        );
        const realCookies = existing
          .filter((c) => !c.value.startsWith(PREFETCH_VALUE_PREFIX))
          .sort((a, b) => {
            // Parse timestamp from "{ts}:{jwe}" — legacy "{jwe}" gets timestamp 0
            const tsA = parseInt(a.value) || 0;
            const tsB = parseInt(b.value) || 0;
            return tsA - tsB; // ascending — oldest first
          });

        let freed = prefetchCookies.reduce(
          (sum, c) =>
            sum + new TextEncoder().encode(`${c.name}=${c.value}`).length,
          0
        );

        const toEvict = [...prefetchCookies];
        if (freed < totalBytes - this.maxSizeBytes + 1) {
          // Phase 1 insufficient — evict oldest real login cookies until under threshold
          for (const c of realCookies) {
            toEvict.push(c);
            freed += new TextEncoder().encode(`${c.name}=${c.value}`).length;
            if (freed >= totalBytes - this.maxSizeBytes + 1) break;
          }
        }

        if (toEvict.length > 0) {
          const evictedPrefetch = toEvict.filter((c) =>
            c.value.startsWith(PREFETCH_VALUE_PREFIX)
          ).length;
          const evictedReal = toEvict.length - evictedPrefetch;
          console.warn(
            `[auth0] Evicting ${toEvict.length} transaction cookie(s) ` +
              `(${totalBytes} bytes ≥ ${this.maxSizeBytes} byte limit): ` +
              `${evictedPrefetch} prefetch, ${evictedReal} real login(s). ` +
              `Increase transactionCookie.maxSizeBytes to reduce eviction of in-flight logins.`
          );
          for (const c of toEvict) {
            cookies.deleteCookie(resCookies, c.name, deleteOptions);
          }
        }
      }
    }

    const expirationSeconds = isPrefetch
      ? PREFETCH_MAX_AGE
      : this.cookieOptions.maxAge!;
    const expiration = Math.floor(Date.now() / 1000 + expirationSeconds);
    const jwe = await cookies.encrypt(
      transactionState,
      this.secret,
      expiration
    );

    // Encode type and creation timestamp in the value for O(1) classification
    // during eviction — no cookie name change, no breaking change.
    // "p:{jwe}"      → prefetch cookie (60s TTL, evicted first)
    // "{ts}:{jwe}"   → real login cookie (FIFO by ts during phase-2 eviction)
    const ts = Math.floor(Date.now() / 1000);
    const encodedValue = isPrefetch
      ? `${PREFETCH_VALUE_PREFIX}${jwe}`
      : `${ts}:${jwe}`;

    const cookieOptions = isPrefetch
      ? { ...this.cookieOptions, maxAge: PREFETCH_MAX_AGE }
      : this.cookieOptions;

    resCookies.set(
      this.getTransactionCookieName(transactionState.state),
      encodedValue,
      cookieOptions
    );
  }

  async get(reqCookies: cookies.RequestCookies, state: string) {
    const cookieName = this.getTransactionCookieName(state);
    const cookieValue = reqCookies.get(cookieName)?.value;

    if (!cookieValue) {
      return null;
    }

    // Strip value prefix before decryption — backward compatible with legacy "{jwe}" format.
    // "p:{jwe}"    → strip "p:" prefix
    // "{ts}:{jwe}" → strip "{ts}:" prefix (find first colon)
    // "{jwe}"      → no prefix, decrypt as-is (legacy)
    const colonIdx = cookieValue.indexOf(":");
    const jwe = colonIdx !== -1 ? cookieValue.slice(colonIdx + 1) : cookieValue;

    return cookies.decrypt<TransactionState>(jwe, this.secret);
  }

  async delete(resCookies: cookies.ResponseCookies, state: string) {
    cookies.deleteCookie(resCookies, this.getTransactionCookieName(state), {
      domain: this.cookieOptions.domain,
      path: this.cookieOptions.path,
      secure: this.cookieOptions.secure,
      sameSite: this.cookieOptions.sameSite,
      httpOnly: this.cookieOptions.httpOnly
    });
  }

  /**
   * Deletes all transaction cookies based on the configured prefix.
   */
  async deleteAll(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    const txnPrefix = this.getCookiePrefix();
    const deleteOptions = {
      domain: this.cookieOptions.domain,
      path: this.cookieOptions.path,
      secure: this.cookieOptions.secure,
      sameSite: this.cookieOptions.sameSite,
      httpOnly: this.cookieOptions.httpOnly
    };

    reqCookies.getAll().forEach((cookie) => {
      if (cookie.name.startsWith(txnPrefix)) {
        cookies.deleteCookie(resCookies, cookie.name, deleteOptions);
      }
    });
  }

  /**
   * Deletes all prefetch-created transaction cookies (value prefix "p:").
   * These are provably garbage — they were created by non-navigational requests
   * and can never lead to a completed OAuth flow.
   *
   * Called on callback success to sweep accumulated prefetch cookies without
   * touching real in-flight logins from other tabs.
   */
  async deletePrefetchCookies(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    const txnPrefix = this.getCookiePrefix();
    const deleteOptions = {
      domain: this.cookieOptions.domain,
      path: this.cookieOptions.path,
      secure: this.cookieOptions.secure,
      sameSite: this.cookieOptions.sameSite,
      httpOnly: this.cookieOptions.httpOnly
    };

    reqCookies.getAll().forEach((cookie) => {
      if (
        cookie.name.startsWith(txnPrefix) &&
        cookie.value.startsWith(PREFETCH_VALUE_PREFIX)
      ) {
        cookies.deleteCookie(resCookies, cookie.name, deleteOptions);
      }
    });
  }
}
