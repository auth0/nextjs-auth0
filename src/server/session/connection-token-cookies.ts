import type { ConnectionTokenSet, CookieOptions } from "../../types/index.js";
import * as cookies from "../cookies/index.js";

// The stateless connection-token cookie prefix. Connection token sets are
// written as `__FC_<index>` (positional chunks), matching the v4
// `StatelessSessionStore.connectionTokenSetsCookieName`.
const CONNECTION_TOKEN_SETS_COOKIE_NAME = "__FC";

// Per-cookie size above which we warn for a single `__FC_*` connection-token
// cookie. Mirrors `FC_COOKIE_SIZE_WARN_BYTES` in the v4 `StatelessSessionStore`:
// 4096 bytes is the per-cookie limit browsers are documented to guarantee.
const FC_COOKIE_SIZE_WARN_BYTES = 4096;

// Emit the per-cookie size warning once per process (writes run on ~every
// authenticated request under rolling sessions). Mirrors the v4 flag.
let fcCookieSizeWarningEmitted = false;

/**
 * Parses the positional index out of a connection-token-set cookie name
 * (e.g. `__FC_2` -> `2`). Returns `null` when the name does not match the exact
 * `<prefix>_<digits>` shape. Mirrors
 * `StatelessSessionStore.parseConnectionTokenSetCookieIndex` so a stray
 * `__FCcustom` cookie set by other code is never treated as ours.
 */
function parseConnectionTokenSetCookieIndex(cookieName: string): number | null {
  const prefix = `${CONNECTION_TOKEN_SETS_COOKIE_NAME}_`;
  if (!cookieName.startsWith(prefix)) {
    return null;
  }
  const suffix = cookieName.slice(prefix.length);
  if (!/^\d+$/.test(suffix)) {
    return null;
  }
  return Number(suffix);
}

/**
 * Reads and decrypts the stateless `__FC_*` connection-token cookies and returns
 * the decrypted `ConnectionTokenSet`s, or `undefined` when none are present.
 *
 * Connection token sets are a nextjs-auth0 concept that stays owned by the
 * connected-accounts code (not the engine state store), so the engine's
 * stateless `get()` never reads them. The v4 `StatelessSessionStore.get`
 * merged them onto the returned `SessionData`
 * (`stateless-session-store.ts:84-107`); this reproduces that read at the
 * session-read choke point during the storage-only cutover.
 *
 * Pure and read-only: never rewrites cookies, never throws (the v4 `decrypt`
 * swallows decryption/expiry errors to `null`). Iterates in `getAll()` order to
 * match the v4 behavior exactly.
 */
export async function readConnectionTokenSetsFromCookies(
  reqCookies: cookies.RequestCookies | cookies.ReadonlyRequestCookies,
  secret: string
): Promise<ConnectionTokenSet[] | undefined> {
  const matching = reqCookies
    .getAll()
    .filter(
      (cookie) => parseConnectionTokenSetCookieIndex(cookie.name) !== null
    );

  const connectionTokenSets: ConnectionTokenSet[] = [];
  for (const cookie of matching) {
    const decrypted = await cookies.decrypt<ConnectionTokenSet>(
      cookie.value,
      secret
    );
    if (decrypted) {
      connectionTokenSets.push(decrypted.payload);
    }
  }

  return connectionTokenSets.length ? connectionTokenSets : undefined;
}

/**
 * Writes the stateless `__FC_*` connection-token cookies and prunes any that are
 * now orphaned, reproducing the v4 `StatelessSessionStore.set` connection-token
 * behavior (`stateless-session-store.ts:157-202`) during the storage-only
 * cutover.
 *
 * - Each connection token set is encrypted (native v4 crypto) into `__FC_<index>`,
 *   set on `resCookies` AND mirrored into `reqCookies` for read-after-write in the
 *   same request.
 * - Every `__FC_<index>` present in `reqCookies` whose index is `>= count` is
 *   deleted (on `resCookies`, mirrored into `reqCookies`). This runs even when
 *   `count` is 0, so a write carrying no connection tokens clears them all -
 *   matching v4. The invariant holds because reads merge `__FC_*` back onto the
 *   session, so ordinary writes re-persist the current set.
 *
 * Stateless only: stateful sessions persist connection token sets inside the
 * backing-store row (via the mapper), never in cookies.
 */
export async function writeConnectionTokenSetsToCookies(
  reqCookies: cookies.RequestCookies,
  resCookies: cookies.ResponseCookies,
  connectionTokenSets: ConnectionTokenSet[] | undefined,
  secret: string,
  cookieConfig: CookieOptions,
  maxAge: number
): Promise<void> {
  const count = connectionTokenSets?.length ?? 0;

  if (count) {
    await Promise.all(
      connectionTokenSets!.map((connectionTokenSet, index) =>
        storeConnectionTokenSetCookie(
          reqCookies,
          resCookies,
          connectionTokenSet,
          `${CONNECTION_TOKEN_SETS_COOKIE_NAME}_${index}`,
          secret,
          cookieConfig,
          maxAge
        )
      )
    );
  }

  // Prune orphaned positional cookies (index beyond the current count).
  const deleteOptions = {
    domain: cookieConfig.domain,
    path: cookieConfig.path,
    secure: cookieConfig.secure,
    sameSite: cookieConfig.sameSite,
    httpOnly: cookieConfig.httpOnly
  };
  for (const cookie of reqCookies.getAll()) {
    const index = parseConnectionTokenSetCookieIndex(cookie.name);
    if (index !== null && index >= count) {
      cookies.deleteCookie(resCookies, cookie.name, deleteOptions);
      // Mirror the deletion so a subsequent get()/set() in the same request does
      // not re-assemble the orphaned cookie into the session.
      reqCookies.delete(cookie.name);
    }
  }
}

/**
 * Deletes every stateless `__FC_*` connection-token cookie present in
 * `reqCookies`, reproducing the v4 `StatelessSessionStore.delete` connection-token
 * sweep (`stateless-session-store.ts:255-257`) during the storage-only cutover.
 *
 * Unlike the write-path prune (which only removes indices `>= count`), this is a
 * FULL sweep of all positional cookies, used when the whole session is being
 * deleted (logout). Deletes on `resCookies` and mirror-deletes on `reqCookies`.
 *
 * Stateless only: stateful sessions never write `__FC_*` cookies (connection
 * token sets live inside the backing-store row via the mapper).
 */
export function deleteConnectionTokenSetsFromCookies(
  reqCookies: cookies.RequestCookies,
  resCookies: cookies.ResponseCookies,
  cookieConfig: CookieOptions
): void {
  const deleteOptions = {
    domain: cookieConfig.domain,
    path: cookieConfig.path,
    secure: cookieConfig.secure,
    sameSite: cookieConfig.sameSite,
    httpOnly: cookieConfig.httpOnly
  };
  for (const cookie of reqCookies.getAll()) {
    if (parseConnectionTokenSetCookieIndex(cookie.name) !== null) {
      cookies.deleteCookie(resCookies, cookie.name, deleteOptions);
      reqCookies.delete(cookie.name);
    }
  }
}

async function storeConnectionTokenSetCookie(
  reqCookies: cookies.RequestCookies,
  resCookies: cookies.ResponseCookies,
  connectionTokenSet: ConnectionTokenSet,
  cookieName: string,
  secret: string,
  cookieConfig: CookieOptions,
  maxAge: number
): Promise<void> {
  const expiration = Math.floor(Date.now() / 1000 + maxAge);
  const jwe = await cookies.encrypt(connectionTokenSet, secret, expiration);
  const cookieValue = jwe.toString();

  resCookies.set(cookieName, cookieValue, { ...cookieConfig, maxAge });
  // Enable read-after-write in the same request (e.g. middleware).
  reqCookies.set(cookieName, cookieValue);

  if (fcCookieSizeWarningEmitted) {
    return;
  }
  const sizeTest = new cookies.ResponseCookies(new Headers());
  sizeTest.set(cookieName, cookieValue, { ...cookieConfig, maxAge });
  if (
    new TextEncoder().encode(sizeTest.toString()).length >=
    FC_COOKIE_SIZE_WARN_BYTES
  ) {
    fcCookieSizeWarningEmitted = true;
    console.warn(
      `The ${cookieName} cookie size exceeds ${FC_COOKIE_SIZE_WARN_BYTES} bytes, which may cause issues in some browsers. ` +
        "You can use a stateful session implementation to store the session data in a data store."
    );
  }
}
