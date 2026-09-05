import type {
  ReadonlyRequestCookies,
  RequestCookies,
  ResponseCookies
} from "../cookies/index.js";
import type { AbstractSessionStore } from "./abstract-session-store.js";
import type { Auth0StatefulStateStore } from "./auth0-stateful-state-store.js";
import type { Auth0StatelessStateStore } from "./auth0-stateless-state-store.js";
import { deleteConnectionTokenSetsFromCookies } from "./connection-token-cookies.js";

export interface DeleteSessionParams {
  /** The engine state store (stateful or stateless) that owns the delete. */
  stateStore: Auth0StatelessStateStore | Auth0StatefulStateStore;
  /** The session cookie name, i.e. the engine store's `identifier`. */
  stateIdentifier: string;
  /**
   * The v4 session store, kept only as the source of mode (`store` set =>
   * stateful) and `cookieConfig` during the storage-only cutover.
   */
  sessionStore: AbstractSessionStore;
  reqCookies: RequestCookies | ReadonlyRequestCookies;
  resCookies: ResponseCookies;
}

/**
 * Deletes a session through the engine state store, reproducing the v4
 * session-store `delete` behavior during the storage-only cutover. Shared by
 * `AuthClient` (both classes hold the same store instances). Pure function, no
 * wrapper class.
 *
 * - Stateful: the engine store resolves the `sid` (native, v4, or v3) and drops
 *   the backing-store row, then clears the `__session` / v3 legacy cookies.
 * - Stateless: the engine store clears the native/v4 `__session` chunks and the
 *   v3 `appSession` cookie. It does NOT own `__FC_*` (connected-accounts stays in
 *   nextjs), so this helper additionally sweeps every `__FC_*` cookie, exactly as
 *   the v4 stateless `delete` did.
 */
export async function deleteSessionFromStateStore({
  stateStore,
  stateIdentifier,
  sessionStore,
  reqCookies,
  resCookies
}: DeleteSessionParams): Promise<void> {
  // The engine cookie context types `reqCookies` as mutable `RequestCookies`.
  // Deletes always operate on a mutable jar; the readonly union only appears on
  // the App Router Server Component path (where a write/delete is attempted and
  // caught by the caller). Cast mirrors slices 1-3.
  const mutableReqCookies = reqCookies as RequestCookies;

  await stateStore.delete(stateIdentifier, {
    reqCookies: mutableReqCookies,
    resCookies
  });

  if (!sessionStore.store) {
    // Stateless: the engine never touches `__FC_*`; sweep them all as v4 did.
    deleteConnectionTokenSetsFromCookies(
      mutableReqCookies,
      resCookies,
      sessionStore.cookieConfig
    );
  }
}

export interface DeleteSessionByReqCookiesParams {
  stateStore: Auth0StatelessStateStore | Auth0StatefulStateStore;
  stateIdentifier: string;
  sessionStore: AbstractSessionStore;
  reqCookies: RequestCookies | ReadonlyRequestCookies;
}

/**
 * Deletes the backing-store record for the session identified by the request
 * cookies, without a response object (IPSIE ceiling enforcement). Reproduces the
 * v4 `deleteByReqCookies` behavior during the storage-only cutover:
 *
 * - Stateful: pass `reqCookies` only. The engine `delete` resolves the `sid` and
 *   drops the row; with no `resCookies` it skips cookie clearing (guarded inside
 *   the engine store), so nothing is written to a response we do not have.
 * - Stateless: no-op. The cookie is the session and clearing it needs a response;
 *   the ceiling check returns null on every subsequent read, so the orphaned
 *   cookie is harmless until its natural max-age.
 */
export async function deleteSessionByReqCookies({
  stateStore,
  stateIdentifier,
  sessionStore,
  reqCookies
}: DeleteSessionByReqCookiesParams): Promise<void> {
  if (!sessionStore.store) {
    // Stateless: matches v4 `deleteByReqCookies` no-op.
    return;
  }

  const mutableReqCookies = reqCookies as RequestCookies;
  await stateStore.delete(stateIdentifier, { reqCookies: mutableReqCookies });
}
