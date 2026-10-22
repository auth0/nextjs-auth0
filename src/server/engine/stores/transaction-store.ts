import {
  AbstractTransactionStore,
  type CookieSerializeOptions,
  type TransactionData
} from "@auth0/auth0-server-js";

import type { TransactionCookieOptions } from "../../types/transaction.js";
import type { CookieContext } from "../context.js";
import type { NextCookieHandler } from "../cookie-handler.js";
import { isLegacyJwe } from "../legacy/legacy-cookies.js";

const TRANSACTION_COOKIE_PREFIX = "__txn_";
const DEFAULT_TRANSACTION_MAX_AGE = 60 * 60;

// Maximum total byte size of all transaction cookies combined. When the projected total meets or
// exceeds this, the oldest cookies are evicted (FIFO by the `{ts}:` value prefix) before the new
// one is written. A JWE is ~450-555 bytes, so this allows ~6 concurrent in-flight logins while
// staying well under browser and proxy request header limits. Same limit as nextjs.
const MAX_TRANSACTION_COOKIE_BYTES = 3500;

// Under prefetch or bot traffic set() runs repeatedly, so warn once per process. Separate flags so
// an operator sees the right diagnostic (accumulation versus a single oversized cookie).
let txnEvictionWarningEmitted = false;
let txnOversizeWarningEmitted = false;

export interface NextTransactionStoreOptions {
  secret: string;
  cookieHandler: NextCookieHandler;
  /**
   * Today's `transactionCookie` options, resolved by the caller (`secure` from the base URL, `path`
   * from the base path, `domain` from `AUTH0_COOKIE_DOMAIN`).
   */
  cookieOptions?: TransactionCookieOptions;
}

/**
 * Holds the login state between `/auth/login` and `/auth/callback`, in the engine format, under
 * the name the engine passes (`__txn_{state}`, or `__txn_` with parallel transactions off).
 *
 * Adds what the engine's own cookie store lacks:
 * - today's cookie options on write and delete (`secure`, `sameSite`, `path`, `domain`, `maxAge`)
 * - a `{ts}:` value prefix and FIFO eviction, keeping all transaction cookies under
 *   {@link MAX_TRANSACTION_COOKIE_BYTES}
 * - `deleteAll`, used by logout and callback errors
 *
 * Expired, tampered and old v4 transaction cookies give no transaction. A login started on v4
 * cannot finish on the engine anyway: v4 sends a `nonce`, which the engine rejects.
 */
export class NextTransactionStore extends AbstractTransactionStore<CookieContext> {
  readonly #cookieHandler: NextCookieHandler;
  readonly #prefix: string;
  readonly #maxAge: number;
  readonly #deleteOptions: CookieSerializeOptions;

  constructor({
    secret,
    cookieHandler,
    cookieOptions
  }: NextTransactionStoreOptions) {
    super({ secret });

    this.#cookieHandler = cookieHandler;
    this.#prefix = cookieOptions?.prefix ?? TRANSACTION_COOKIE_PREFIX;
    // `||`, as on nextjs: a `maxAge` of 0 gives the default.
    this.#maxAge = cookieOptions?.maxAge || DEFAULT_TRANSACTION_MAX_AGE;
    this.#deleteOptions = {
      httpOnly: true,
      // `lax` is required so the cookie is sent on the callback redirect.
      sameSite: cookieOptions?.sameSite ?? "lax",
      secure: cookieOptions?.secure ?? false,
      path: cookieOptions?.path ?? "/",
      ...(cookieOptions?.domain ? { domain: cookieOptions.domain } : {})
    };
  }

  async set(
    identifier: string,
    transactionData: TransactionData,
    // Writing a cookie with the same name replaces it, as in the engine's store.
    _removeIfExists?: boolean,
    ctx?: CookieContext
  ): Promise<void> {
    if (!ctx?.resCookies) {
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const jwe = await this.encrypt(
      identifier,
      transactionData,
      now + this.#maxAge
    );
    const value = `${now}:${jwe}`;

    this.#evictOldest(ctx, identifier, value);

    this.#cookieHandler.setCookie(
      identifier,
      value,
      { ...this.#deleteOptions, maxAge: this.#maxAge },
      ctx
    );
  }

  async get(
    identifier: string,
    ctx?: CookieContext
  ): Promise<TransactionData | undefined> {
    const cookieValue = this.#cookieHandler.getCookie(identifier, ctx);
    if (!cookieValue) {
      return undefined;
    }

    // Strip the `{ts}:` prefix; a bare value (no colon) is used as is.
    const colonIdx = cookieValue.indexOf(":");
    const jwe = colonIdx !== -1 ? cookieValue.slice(colonIdx + 1) : cookieValue;

    // The engine throws for a JWE without `kid` and for an expired one; both are no transaction.
    if (isLegacyJwe(jwe)) {
      return undefined;
    }
    try {
      return await this.decrypt<TransactionData>(identifier, jwe);
    } catch (e: any) {
      if (e?.code === "ERR_JWT_EXPIRED") {
        return undefined;
      }
      throw e;
    }
  }

  async delete(identifier: string, ctx?: CookieContext): Promise<void> {
    this.#cookieHandler.deleteCookie(identifier, ctx, this.#deleteOptions);
  }

  /**
   * Deletes every transaction cookie in the request. Not part of the engine interface.
   */
  deleteAll(ctx: CookieContext): void {
    for (const { name } of this.#transactionCookies(ctx)) {
      this.#cookieHandler.deleteCookie(name, ctx, this.#deleteOptions);
    }
  }

  /**
   * Evicts the oldest transaction cookies so that all of them, including the one about to be
   * written, stay under {@link MAX_TRANSACTION_COOKIE_BYTES}. The cookie about to be (re)written
   * is never evicted. Same logic and warnings as nextjs.
   */
  #evictOldest(ctx: CookieContext, newName: string, newValue: string): void {
    const txnCookies = this.#transactionCookies(ctx);

    // A cookie with the same name as the new one is replaced, so its bytes are not added.
    const existingBytes = txnCookies.reduce(
      (sum, c) => (c.name === newName ? sum : sum + sizeOf(c.name, c.value)),
      0
    );
    const projectedBytes = existingBytes + sizeOf(newName, newValue);

    if (projectedBytes < MAX_TRANSACTION_COOKIE_BYTES) {
      return;
    }

    const sorted = [...txnCookies].sort(
      (a, b) => parseCookieTimestamp(a.value) - parseCookieTimestamp(b.value)
    );

    let freed = 0;
    const target = projectedBytes - MAX_TRANSACTION_COOKIE_BYTES + 1;
    for (const c of sorted) {
      if (c.name === newName) continue;
      this.#cookieHandler.deleteCookie(c.name, ctx, this.#deleteOptions);
      freed += sizeOf(c.name, c.value);
      if (freed >= target) break;
    }

    if (freed > 0) {
      if (!txnEvictionWarningEmitted) {
        txnEvictionWarningEmitted = true;
        console.warn(
          `[auth0] Evicted the oldest transaction cookie(s) — projected total size ${projectedBytes} bytes ` +
            `reached the ${MAX_TRANSACTION_COOKIE_BYTES} byte limit. This usually means many ` +
            `login flows were started but never completed (e.g. prefetches or abandoned logins); ` +
            `reduce transactionCookie.maxAge if in-flight logins are being evicted too aggressively.`
        );
      }
    } else if (!txnOversizeWarningEmitted) {
      txnOversizeWarningEmitted = true;
      console.warn(
        `[auth0] Transaction cookie exceeds the ${MAX_TRANSACTION_COOKIE_BYTES} byte limit ` +
          `on its own (projected size ${projectedBytes} bytes). This is usually caused by a very ` +
          `long returnTo, scope, or audience value on /auth/login. Check the field clamps in ` +
          `handleLogin; the cookie was still written but may be rejected by the browser or a proxy.`
      );
    }
  }

  // The request cookies whose names start with the transaction prefix.
  #transactionCookies(ctx: CookieContext): { name: string; value: string }[] {
    return ctx.reqCookies
      .getAll()
      .filter((c) => c.name.startsWith(this.#prefix));
  }
}

function sizeOf(name: string, value: string): number {
  return new TextEncoder().encode(`${name}=${value}`).length;
}

// The creation time from a `{ts}:{jwe}` value. A bare value (no colon) sorts first (0). Split on
// the first colon so a bare JWE that starts with digits is never read as a timestamp.
function parseCookieTimestamp(value: string): number {
  const colonIdx = value.indexOf(":");
  if (colonIdx === -1) {
    return 0;
  }
  const ts = Number(value.slice(0, colonIdx));
  return Number.isFinite(ts) ? ts : 0;
}
