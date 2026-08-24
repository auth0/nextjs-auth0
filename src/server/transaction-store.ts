import type * as jose from "jose";

import { RESPONSE_TYPES } from "../types/index.js";
import * as cookies from "./cookies.js";

const TRANSACTION_COOKIE_PREFIX = "__txn_";

// Maximum total byte size of all transaction (`__txn_*`) cookies
// combined. When the accumulated size meets or exceeds this limit, the oldest
// cookies are evicted (FIFO by creation timestamp) before a new one is written.
// One JWE is ~450–555 bytes, so this allows ~6 concurrent in-flight logins —
// enough for multi-tab use while staying well under the request-header limits
// enforced by browsers (~4 KB per cookie) and servers/proxies. Intentionally
// fixed and not configurable: it caps transaction-cookie accumulation regardless
// of the deployment's header limit, which the SDK cannot know.
const MAX_TRANSACTION_COOKIE_BYTES = 3500;

// Ceiling on `returnTo` length, in bytes of the encoded URL. `returnTo` is the
// only user-influenced field in `TransactionState` that can grow arbitrarily
// long, and a very long value can push the resulting transaction cookie past
// `MAX_TRANSACTION_COOKIE_BYTES` on its own — which the FIFO eviction below
// cannot fix (there's nothing to evict that would make room). Anything longer
// than this is clamped back to `signInReturnToPath` by `clampReturnTo` and
// warned once. 2 KB is well above any realistic post-login path and well under
// the ~3 KB budget available for `returnTo` inside the JWE + cookie envelope.
export const MAX_RETURN_TO_BYTES = 2048;

// Emit once per process — same reasoning as sessionSizeWarningEmitted in
// stateless-session-store.ts: prefetch/bot traffic hits this path repeatedly,
// so a per-eviction warn would spam logs.
let txnEvictionWarningEmitted = false;

// Also once-per-process for the same reason.
let returnToClampWarningEmitted = false;

/**
 * If `returnTo` would push the transaction cookie past
 * `MAX_TRANSACTION_COOKIE_BYTES`, clamp it back to `fallback` and warn once.
 * Returning `fallback` instead of throwing preserves the login flow — the user
 * lands on the default post-login path instead of hitting a 500. This is safe
 * because `toSafeRedirect` has already validated `returnTo` is same-origin;
 * silently clamping cannot leak the user to an attacker-controlled URL.
 */
export function clampReturnTo(returnTo: string, fallback: string): string {
  if (new TextEncoder().encode(returnTo).length <= MAX_RETURN_TO_BYTES) {
    return returnTo;
  }
  if (!returnToClampWarningEmitted) {
    returnToClampWarningEmitted = true;
    console.warn(
      `[auth0] returnTo value exceeds ${MAX_RETURN_TO_BYTES} bytes; clamping to ` +
        `${fallback} to keep the transaction cookie under the header size limit. ` +
        `Shorten the returnTo URL in your application.`
    );
  }
  return fallback;
}

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
   * Specifies the value for the {@link https://tools.ietf.org/html/rfc6265#section-5.2.3 | Domain Set-Cookie attribute}. By default, no
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

  constructor({
    secret,
    cookieOptions,
    enableParallelTransactions
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
   * @param reqCookies - Optional request cookies. When provided, enables FIFO
   *                     eviction of accumulated transaction cookies (capped at
   *                     {@link MAX_TRANSACTION_COOKIE_BYTES}) before writing the
   *                     new cookie.
   * @throws {Error} When transaction state is missing required state parameter
   */
  async save(
    resCookies: cookies.ResponseCookies,
    transactionState: TransactionState,
    reqCookies?: cookies.RequestCookies | cookies.ReadonlyRequestCookies
  ) {
    if (!transactionState.state) {
      throw new Error("Transaction state is required");
    }

    const expiration = Math.floor(
      Date.now() / 1000 + this.cookieOptions.maxAge!
    );
    const jwe = await cookies.encrypt(
      transactionState,
      this.secret,
      expiration
    );

    // Encode creation timestamp in the value for O(1) FIFO ordering during eviction.
    // Format: "{ts}:{jwe}" — cookie name is unchanged.
    //
    // Compatibility notes:
    // - Forward (new code reads old cookie): get() strips a "{ts}:" prefix
    //   before decrypting, so legacy bare "{jwe}" values still read correctly.
    //   See `get()` below.
    // - Backward (old code reads new cookie): a version of get() that predates
    //   this change passes the full "{ts}:{jwe}" string to decrypt(), which
    //   returns null (ERR_JWE_INVALID is swallowed). Any in-flight login
    //   started against a pod with this write-side change but completed against
    //   a pod without the read-side prefix stripping will fail once — the user
    //   sees "state parameter is invalid" and must re-initiate login. This
    //   affects rolling deploys where old and new pods coexist, and rollbacks.
    //   Transaction cookies are short-lived (default maxAge 1h), so the window
    //   is bounded to one hour after the deploy/rollback boundary.
    //
    //   To eliminate the window, ship the get() prefix-stripping in a prior
    //   backfill release; then every pod can read the new format before the
    //   first pod writes it. If that is not feasible, call out the one-time
    //   in-flight login failure in the release notes.
    const ts = Math.floor(Date.now() / 1000);
    const newCookieName = this.getTransactionCookieName(transactionState.state);
    const newCookieValue = `${ts}:${jwe}`;

    // Evict oldest transaction cookies FIFO before writing the new one, so the
    // accumulated `__txn_*` cookies stay under the fixed byte limit. Only
    // transaction cookies are measured/deleted — the session and other cookies
    // are left untouched, and the cookie about to be written is never evicted.
    if (reqCookies) {
      this.evictOldestTransactionCookies(
        reqCookies,
        resCookies,
        newCookieName,
        newCookieValue
      );
    }

    resCookies.set(newCookieName, newCookieValue, this.cookieOptions);
  }

  /**
   * Evicts the oldest transaction cookies (FIFO by the `{ts}:` value prefix) from
   * the response so that the accumulated `__txn_*` cookies — including the one
   * about to be written — stay under {@link MAX_TRANSACTION_COOKIE_BYTES}.
   *
   * Only cookies matching the transaction prefix are measured and deleted — the
   * session, connection-token, and application cookies are never touched. The
   * cookie about to be (re)written for the current transaction (`newCookieName`)
   * is never evicted. No-op when the projected total is under the limit.
   *
   * @param newCookieName - Name of the cookie about to be written (never evicted).
   * @param newCookieValue - Value of that cookie; its size is included in the cap
   *                         so a large new cookie can still trigger eviction.
   */
  private evictOldestTransactionCookies(
    reqCookies: cookies.RequestCookies | cookies.ReadonlyRequestCookies,
    resCookies: cookies.ResponseCookies,
    newCookieName: string,
    newCookieValue: string
  ) {
    const sizeOf = (name: string, value: string) =>
      new TextEncoder().encode(`${name}=${value}`).length;

    const txnCookies = reqCookies
      .getAll()
      .filter((c) => c.name.startsWith(this.transactionCookiePrefix));

    // Existing transaction-cookie bytes, excluding any cookie with the same name
    // as the one we're about to write — its old bytes are replaced, not added.
    const existingBytes = txnCookies.reduce(
      (sum, c) =>
        c.name === newCookieName ? sum : sum + sizeOf(c.name, c.value),
      0
    );
    // Project the total that will be on the request header after this write.
    const projectedBytes =
      existingBytes + sizeOf(newCookieName, newCookieValue);

    if (projectedBytes < MAX_TRANSACTION_COOKIE_BYTES) {
      return;
    }

    const deleteOptions = {
      domain: this.cookieOptions.domain,
      path: this.cookieOptions.path,
      secure: this.cookieOptions.secure,
      sameSite: this.cookieOptions.sameSite,
      httpOnly: this.cookieOptions.httpOnly
    };

    // Sort by timestamp encoded in value prefix "{ts}:{jwe}".
    // Legacy bare "{jwe}" values (no colon) get timestamp 0 — evicted first.
    const sorted = [...txnCookies].sort(
      (a, b) =>
        this.parseCookieTimestamp(a.value) - this.parseCookieTimestamp(b.value)
    );

    let freed = 0;
    const target = projectedBytes - MAX_TRANSACTION_COOKIE_BYTES + 1;
    for (const c of sorted) {
      // Never evict the cookie we are about to (re)write for this state.
      if (c.name === newCookieName) continue;
      cookies.deleteCookie(resCookies, c.name, deleteOptions);
      freed += sizeOf(c.name, c.value);
      if (freed >= target) break;
    }

    if (!txnEvictionWarningEmitted) {
      txnEvictionWarningEmitted = true;
      console.warn(
        `[auth0] Evicted the oldest transaction cookie(s) — projected total size ${projectedBytes} bytes ` +
          `reached the ${MAX_TRANSACTION_COOKIE_BYTES} byte limit. This usually means many ` +
          `login flows were started but never completed (e.g. prefetches or abandoned logins); ` +
          `reduce transactionCookie.maxAge if in-flight logins are being evicted too aggressively.`
      );
    }
  }

  /**
   * Extracts the creation timestamp from a cookie value shaped "{ts}:{jwe}".
   * Legacy bare "{jwe}" values (no colon) have no timestamp and sort first (0).
   * Uses an explicit split on the first colon rather than `parseInt`, so a
   * legacy JWE that happens to start with digits is never mistaken for a
   * timestamp — consistent with the split used in {@link get}.
   */
  private parseCookieTimestamp(value: string): number {
    const colonIdx = value.indexOf(":");
    if (colonIdx === -1) {
      return 0;
    }
    const ts = Number(value.slice(0, colonIdx));
    return Number.isFinite(ts) ? ts : 0;
  }

  async get(reqCookies: cookies.RequestCookies, state: string) {
    const cookieName = this.getTransactionCookieName(state);
    const cookieValue = reqCookies.get(cookieName)?.value;

    if (!cookieValue) {
      return null;
    }

    // Strip "{ts}:" prefix before decryption — backward compatible with legacy bare "{jwe}".
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
}
