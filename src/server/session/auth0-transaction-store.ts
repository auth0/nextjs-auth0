import {
  CookieTransactionStore,
  type CookieHandler,
  type CookieSerializeOptions,
  type EncryptedStoreOptions,
  type TransactionData
} from "@auth0/auth0-server-js";

import type { Auth0CookieContext } from "../auth-client/auth0-cookie-handler.js";
import { decrypt as decryptV4 } from "../cookies/index.js";

// Default transaction cookie prefix, matching the current v4 `TransactionStore`
// (`__txn_`). The real value is threaded in from config during ServerClient
// wiring; this is only the fallback when none is supplied.
export const DEFAULT_TRANSACTION_COOKIE_PREFIX = "__txn_";

/**
 * Computes the (optionally state-scoped) transaction cookie name, i.e. the
 * `identifier` the name-agnostic {@link Auth0TransactionStore} expects. Mirrors
 * the v4 `TransactionStore.getTransactionCookieName` exactly: in parallel mode
 * the state is appended (`${prefix}${state}`) so multiple in-flight logins get
 * distinct cookies; otherwise the bare prefix is used (single transaction).
 *
 * The engine's own `ServerClient` computes this internally, but the storage-only
 * cutover drives the store directly (no `ServerClient`), so the caller owns the
 * name. Kept as a pure function (not a class) to avoid a wrapper layer.
 */
export function transactionIdentifier(
  prefix: string,
  state: string,
  enableParallelTransactions: boolean
): string {
  return enableParallelTransactions ? `${prefix}${state}` : prefix;
}

// Default transaction cookie lifetime (1 hour), matching the current
// `TransactionStore` default.
const DEFAULT_TRANSACTION_MAX_AGE = 60 * 60;

// Maximum total byte size of all transaction (`${prefix}*`) cookies combined.
// When the projected total meets or exceeds this, the oldest cookies are
// evicted (FIFO by the `{ts}:` value prefix) before the new one is written.
// Matches the cap and rationale of the current `TransactionStore`: a JWE is
// ~450-555 bytes, so this allows ~6 concurrent in-flight logins while staying
// well under browser/proxy request-header limits.
const MAX_TRANSACTION_COOKIE_BYTES = 3500;

// Emit each warning once per process. Under prefetch/bot traffic `set()` runs
// repeatedly, so a per-write warn would spam logs. Mirrors the flags in the
// current `TransactionStore`.
let txnEvictionWarningEmitted = false;
let txnOversizeWarningEmitted = false;

// `EncryptedStoreOptions.secret` is `string | string[]` (secret rotation). The
// nextjs-auth0 v4 crypto helper takes a single secret, so we try each in order,
// exactly as the engine does for its native decrypt.
function toSecrets(secret: string | string[]): string[] {
  return Array.isArray(secret) ? secret : [secret];
}

// Values are stored as `{ts}:{jwe}`. Strip the `{ts}:` prefix before decrypting.
// Legacy bare `{jwe}` values (no colon) are returned unchanged.
function stripTimestampPrefix(value: string): string {
  const colonIdx = value.indexOf(":");
  return colonIdx !== -1 ? value.slice(colonIdx + 1) : value;
}

// Extract the creation timestamp from a `{ts}:{jwe}` value for FIFO ordering.
// Legacy bare `{jwe}` values (no colon) sort first (0). Uses an explicit split
// on the first colon so a legacy JWE starting with digits is never mistaken for
// a timestamp.
function parseCookieTimestamp(value: string): number {
  const colonIdx = value.indexOf(":");
  if (colonIdx === -1) {
    return 0;
  }
  const ts = Number(value.slice(0, colonIdx));
  return Number.isFinite(ts) ? ts : 0;
}

function sizeOf(name: string, value: string): number {
  return new TextEncoder().encode(`${name}=${value}`).length;
}

/**
 * Cookie attributes honored on transaction-cookie write and delete. The engine
 * base (`CookieTransactionStore`) hardcodes `{ httpOnly, sameSite: "lax",
 * path: "/", maxAge: 3600 }` and drops `secure` / `domain` / a configurable
 * `maxAge`, so we carry them here to preserve the current `TransactionStore`
 * behavior.
 */
export interface Auth0TransactionCookieOptions {
  secure?: boolean;
  domain?: string;
  path?: string;
  sameSite?: "lax" | "strict" | "none";
  maxAge?: number;
}

export interface Auth0TransactionStoreOptions {
  /**
   * The transaction cookie prefix, i.e. the same value passed to the engine as
   * `transactionIdentifier`. Used to scope FIFO eviction and `deleteAll` to
   * this store's own cookies. Defaults to `"__txn_"`.
   */
  transactionCookiePrefix?: string;
  /**
   * Cookie attributes honored on write / delete (the engine base ignores
   * `secure` / `domain` / `maxAge`).
   */
  cookieOptions?: Auth0TransactionCookieOptions;
}

/**
 * Transaction store on top of auth0-server-js. Holds the short-lived
 * "login in progress" state between `/auth/login` and `/auth/callback`.
 *
 * Writes the engine's native A256CBC-HS512 format under the configured cookie
 * name, and re-adds the storage-layer behaviors the engine base does not own:
 *
 * - `set`: native encrypt, then a `{ts}:` timestamp prefix for FIFO ordering,
 *   then FIFO eviction so accumulated `${prefix}*` cookies stay under
 *   {@link MAX_TRANSACTION_COOKIE_BYTES}, honoring the configurable cookie
 *   attributes (`secure` / `domain` / `maxAge`) the engine drops.
 * - `get`: strip `{ts}:`, decrypt native, then fall back to the legacy v4
 *   A256GCM format so an in-flight login started before a migration deploy
 *   still completes. Transactions never had a v3 format, so there is no third
 *   reader here.
 * - `delete` / `deleteAll`: honor the configured attributes; `deleteAll` sweeps
 *   every `${prefix}*` cookie (used by logout / error paths).
 *
 * This store is name-agnostic: the (optionally state-scoped) cookie name is
 * handed down by the engine as `identifier`. It never computes the `state`
 * scope itself. Field clamping (`clampReturnTo` / `clampTransactionField`) is
 * NOT here: those operate on `returnTo` / `scope` / `audience` before the
 * transaction is built, which is the login handler's concern.
 */
export class Auth0TransactionStore extends CookieTransactionStore<Auth0CookieContext> {
  // The base keeps its own private `#cookieHandler`; hold our own reference
  // because we fully override set/get/delete.
  readonly #cookieHandler: CookieHandler<Auth0CookieContext>;
  readonly #prefix: string;
  readonly #cookieOptions: Auth0TransactionCookieOptions;

  constructor(
    options: EncryptedStoreOptions,
    cookieHandler: CookieHandler<Auth0CookieContext>,
    storeOptions?: Auth0TransactionStoreOptions
  ) {
    super(options, cookieHandler);
    this.#cookieHandler = cookieHandler;
    this.#prefix =
      storeOptions?.transactionCookiePrefix ??
      DEFAULT_TRANSACTION_COOKIE_PREFIX;
    this.#cookieOptions = storeOptions?.cookieOptions ?? {};
  }

  override async set(
    identifier: string,
    transactionData: TransactionData,
    // The engine base ignores `removeIfExists` for cookie transactions (a write
    // overwrites the same name); we match that.
    _removeIfExists?: boolean,
    options?: Auth0CookieContext
  ): Promise<void> {
    // No response to write to (e.g. a Server Component). The engine base has
    // the same limitation.
    if (!options?.resCookies) {
      return;
    }

    const maxAge = this.#cookieOptions.maxAge ?? DEFAULT_TRANSACTION_MAX_AGE;
    const expiration = Math.floor(Date.now() / 1000) + maxAge;
    const encrypted = await this.encrypt(
      identifier,
      transactionData,
      expiration
    );

    // Prepend a creation timestamp for O(1) FIFO ordering during eviction.
    // Format `{ts}:{jwe}`; `get()` strips it before decrypting.
    const ts = Math.floor(Date.now() / 1000);
    const value = `${ts}:${encrypted}`;

    // Evict the oldest transaction cookies before writing, so the accumulated
    // `${prefix}*` cookies (including this one) stay under the byte cap.
    this.#evictOldest(options, identifier, value);

    this.#cookieHandler.setCookie(
      identifier,
      value,
      this.#writeAttributes(maxAge),
      options
    );
  }

  override async get(
    identifier: string,
    options?: Auth0CookieContext
  ): Promise<TransactionData | undefined> {
    const raw = this.#cookieHandler.getCookie(identifier, options);
    if (!raw) {
      return undefined;
    }

    const value = stripTimestampPrefix(raw);

    // Native A256CBC-HS512 first (what we write now).
    try {
      const native = await this.decrypt<TransactionData>(identifier, value);
      if (native) {
        return native;
      }
    } catch {
      // Expired native cookie or a non-native value under the same name; fall
      // through to the legacy v4 read below (which returns undefined if it is
      // genuinely native-but-expired).
    }

    // Legacy v4 (A256GCM) fallback so an in-flight login started before the
    // deploy still completes. Transactions never had a v3 format.
    return this.#readLegacyV4(value);
  }

  override async delete(
    identifier: string,
    options?: Auth0CookieContext
  ): Promise<void> {
    this.#cookieHandler.deleteCookie(
      identifier,
      options,
      this.#deleteAttributes()
    );
  }

  /**
   * Deletes every transaction cookie (`${prefix}*`). Needed by the logout and
   * callback-error paths until the full ServerClient swap removes those call
   * sites. Not part of the engine's transaction-store interface (additive).
   */
  deleteAll(options?: Auth0CookieContext): void {
    if (!options?.resCookies) {
      return;
    }
    const all = this.#cookieHandler.getCookies(options);
    for (const name of Object.keys(all)) {
      if (name.startsWith(this.#prefix)) {
        this.#cookieHandler.deleteCookie(
          name,
          options,
          this.#deleteAttributes()
        );
      }
    }
  }

  /**
   * Reads a legacy v4 transaction cookie (A256GCM), trying each rotation
   * secret. Returns the decrypted `TransactionData` or `undefined`. Never
   * throws (the v4 `decrypt` swallows decryption/expiry errors to `null`).
   */
  async #readLegacyV4(value: string): Promise<TransactionData | undefined> {
    for (const secret of toSecrets(this.options.secret)) {
      const result = await decryptV4<TransactionData>(value, secret);
      if (result) {
        return result.payload;
      }
    }
    return undefined;
  }

  /**
   * Evicts the oldest transaction cookies (FIFO by the `{ts}:` value prefix) so
   * that the accumulated `${prefix}*` cookies, including the one about to be
   * written, stay under {@link MAX_TRANSACTION_COOKIE_BYTES}. Only cookies
   * matching this store's prefix are measured / deleted; the cookie about to be
   * (re)written is never evicted. No-op when the projected total is under the
   * limit. Ported from the current `TransactionStore`.
   */
  #evictOldest(
    options: Auth0CookieContext,
    newName: string,
    newValue: string
  ): void {
    const all = this.#cookieHandler.getCookies(options);
    const txn = Object.entries(all).filter(([name]) =>
      name.startsWith(this.#prefix)
    );

    // Existing transaction-cookie bytes, excluding any cookie with the same
    // name as the one we are about to write (its bytes are replaced, not added).
    const existingBytes = txn.reduce(
      (sum, [name, value]) =>
        name === newName ? sum : sum + sizeOf(name, value),
      0
    );
    const projectedBytes = existingBytes + sizeOf(newName, newValue);

    if (projectedBytes < MAX_TRANSACTION_COOKIE_BYTES) {
      return;
    }

    const sorted = [...txn].sort(
      ([, a], [, b]) => parseCookieTimestamp(a) - parseCookieTimestamp(b)
    );

    let freed = 0;
    const target = projectedBytes - MAX_TRANSACTION_COOKIE_BYTES + 1;
    for (const [name, value] of sorted) {
      // Never evict the cookie we are about to (re)write for this transaction.
      if (name === newName) {
        continue;
      }
      this.#cookieHandler.deleteCookie(name, options, this.#deleteAttributes());
      freed += sizeOf(name, value);
      if (freed >= target) {
        break;
      }
    }

    if (freed > 0) {
      // Something was actually evicted: the accumulation-of-abandoned-logins
      // diagnostic is the right one. Guarded by `freed > 0` so we do not send
      // an operator hunting for phantom abandoned logins when the real issue is
      // a single oversized cookie (see the else branch).
      if (!txnEvictionWarningEmitted) {
        txnEvictionWarningEmitted = true;
        console.warn(
          `[auth0] Evicted the oldest transaction cookie(s), projected total size ${projectedBytes} bytes ` +
            `reached the ${MAX_TRANSACTION_COOKIE_BYTES} byte limit. This usually means many ` +
            `login flows were started but never completed (e.g. prefetches or abandoned logins); ` +
            `reduce transactionCookie.maxAge if in-flight logins are being evicted too aggressively.`
        );
      }
    } else {
      // Nothing was evicted but the cap is still exceeded: the new cookie is
      // bigger than the cap on its own. Usually a very long returnTo, scope, or
      // audience slipped past the field clamps. Different message so the
      // operator does not go looking for accumulation.
      if (!txnOversizeWarningEmitted) {
        txnOversizeWarningEmitted = true;
        console.warn(
          `[auth0] Transaction cookie exceeds the ${MAX_TRANSACTION_COOKIE_BYTES} byte limit ` +
            `on its own (projected size ${projectedBytes} bytes). This is usually caused by a very ` +
            `long returnTo, scope, or audience value on /auth/login. Check the field clamps in the ` +
            `login handler; the cookie was still written but may be rejected by the browser or a proxy.`
        );
      }
    }
  }

  #writeAttributes(maxAge: number): CookieSerializeOptions {
    return {
      httpOnly: true,
      // `lax` is required so the cookie is sent on the callback redirect.
      sameSite: this.#cookieOptions.sameSite ?? "lax",
      secure: this.#cookieOptions.secure ?? false,
      path: this.#cookieOptions.path ?? "/",
      maxAge,
      ...(this.#cookieOptions.domain
        ? { domain: this.#cookieOptions.domain }
        : {})
    };
  }

  #deleteAttributes(): CookieSerializeOptions {
    // Browsers match a deletion on the same domain/path/secure/sameSite the
    // cookie was written with, so mirror the write attributes (minus maxAge).
    return {
      httpOnly: true,
      sameSite: this.#cookieOptions.sameSite ?? "lax",
      secure: this.#cookieOptions.secure ?? false,
      path: this.#cookieOptions.path ?? "/",
      ...(this.#cookieOptions.domain
        ? { domain: this.#cookieOptions.domain }
        : {})
    };
  }
}
