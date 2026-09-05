import type { SessionData } from "../../types/index.js";
import type {
  ReadonlyRequestCookies,
  RequestCookies,
  ResponseCookies
} from "../cookies/index.js";
import type { AbstractSessionStore } from "./abstract-session-store.js";
import type { Auth0StatefulStateStore } from "./auth0-stateful-state-store.js";
import type { Auth0StatelessStateStore } from "./auth0-stateless-state-store.js";
import { writeConnectionTokenSetsToCookies } from "./connection-token-cookies.js";
import { sessionDataToStateData } from "./session-mapper.js";

export interface SaveSessionParams {
  /** The engine state store (stateful or stateless) that owns the write. */
  stateStore: Auth0StatelessStateStore | Auth0StatefulStateStore;
  /** The session cookie name, i.e. the engine store's `identifier`. */
  stateIdentifier: string;
  /**
   * The v4 session store, kept only as the source of truth for mode
   * (`store` set => stateful), `secret`, `cookieConfig`, and `calculateMaxAge`
   * during the storage-only cutover.
   */
  sessionStore: AbstractSessionStore;
  reqCookies: RequestCookies | ReadonlyRequestCookies;
  resCookies: ResponseCookies;
  session: SessionData;
  /** New login: regenerate the session id (stateful) / overwrite (stateless). */
  isNew?: boolean;
}

/**
 * Writes a session through the engine state store in its native format,
 * reproducing the v4 session-store write behavior during the storage-only
 * cutover. Shared by `AuthClient` and `Auth0Client` (both hold the same store
 * instances). Pure function, no wrapper class.
 *
 * - Stateful: the engine store persists the mapped row; `connectionTokenSets`
 *   round-trip into the row via the mapper (slice 2 pass-through).
 * - Stateless: `connectionTokenSets` are stripped from the `__session` cookie and
 *   written / pruned as `__FC_*` cookies, exactly as the v4 stateless store did.
 *   The engine store still owns the native `__session` write, its size warning,
 *   and the legacy v3 `appSession` cleanup.
 */
export async function saveSessionToStateStore({
  stateStore,
  stateIdentifier,
  sessionStore,
  reqCookies,
  resCookies,
  session,
  isNew
}: SaveSessionParams): Promise<void> {
  // The engine cookie context types `reqCookies` as mutable `RequestCookies`.
  // Writes always operate on a mutable jar; the readonly union only appears on
  // the App Router Server Component path, where a write is attempted and caught
  // by the caller exactly as with the v4 store. Cast mirrors slices 1-2.
  const mutableReqCookies = reqCookies as RequestCookies;
  const ctx = { reqCookies: mutableReqCookies, resCookies };
  const stateData = sessionDataToStateData(session);

  if (sessionStore.store) {
    // Stateful: connectionTokenSets are carried into the row by the mapper.
    await stateStore.set(stateIdentifier, stateData, isNew, ctx);
    return;
  }

  // Stateless: keep connectionTokenSets out of `__session`; manage `__FC_*`.
  const { connectionTokenSets: _fc, ...stateWithoutFc } = stateData;
  await stateStore.set(stateIdentifier, stateWithoutFc, isNew, ctx);

  const maxAge = sessionStore.calculateMaxAge(session.internal.createdAt);
  await writeConnectionTokenSetsToCookies(
    mutableReqCookies,
    resCookies,
    session.connectionTokenSets,
    sessionStore.secret,
    sessionStore.cookieConfig,
    maxAge
  );
}
