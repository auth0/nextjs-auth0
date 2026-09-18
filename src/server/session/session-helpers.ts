import type { StateData, TokenResponse } from "@auth0/auth0-server-js";

import type { AccessTokenSet, SessionData } from "../../types/index.js";
import { TransactionState } from "../transaction-store.js";
import { filterDefaultIdTokenClaims } from "../user.js";
import {
  sessionDataToStateData,
  stateDataToSessionData
} from "./session-mapper.js";

const SESSION_EXPIRY_LEEWAY_SECONDS = 30;

/**
 * The validated ID token claims carried on the engine's {@link TokenResponse}
 * (`session_expiry` and the standard OIDC claims). Referenced structurally so
 * the session layer does not import a claims type the engine does not export.
 */
type IdTokenClaims = NonNullable<TokenResponse["claims"]>;

/**
 * The finalize hook shape shared by the handler-level `finalizeSession` and the
 * engine store's in-`set()` finalize. Structurally identical to
 * `BeforeSessionSavedHook`; declared here so the session layer does not import
 * from the auth-client layer.
 */
export type SessionFinalizeHook = (
  session: SessionData,
  idToken: string | null
) => Promise<SessionData>;

/**
 * The single session-finalization step. Runs the consumer's
 * `beforeSessionSaved` hook when configured (preserving `session.internal` so a
 * hook cannot drop it), otherwise reduces `session.user` to the default ID
 * token claims. `Auth0ServerClient.finalizeSession` and the engine store's
 * `set()` both delegate here so the two can never diverge.
 */
export async function finalizeSessionData(
  session: SessionData,
  idToken: string | null,
  beforeSessionSaved?: SessionFinalizeHook
): Promise<SessionData> {
  if (beforeSessionSaved) {
    const updatedSession = await beforeSessionSaved(session, idToken);
    return { ...updatedSession, internal: session.internal };
  }
  session.user = filterDefaultIdTokenClaims(session.user);
  return session;
}

/**
 * The engine store's `set()` is handed engine `StateData`, but
 * `beforeSessionSaved` operates on nextjs-auth0 `SessionData`. When (and only
 * when) the per-request cookie context opts in via `runBeforeSessionSaved`, map
 * the outgoing `StateData` to `SessionData`, run {@link finalizeSessionData},
 * and map back, so the engine's own single write persists the transformed
 * session. The `idToken` the hook receives is the one already carried on the
 * session (`session.tokenSet.idToken`); at every finalize site today that value
 * equals the id_token being written.
 *
 * A no-op (returns the input unchanged) when the marker is absent, so the
 * session writes that bypass the hook today keep bypassing it, and returns the
 * input unchanged for a `StateData` that has no representable session.
 */
export async function finalizeStateData(
  stateData: StateData,
  runBeforeSessionSaved: boolean | undefined,
  beforeSessionSaved?: SessionFinalizeHook
): Promise<StateData> {
  if (!runBeforeSessionSaved) {
    return stateData;
  }
  const session = stateDataToSessionData(stateData);
  if (!session) {
    return stateData;
  }
  const finalized = await finalizeSessionData(
    session,
    session.tokenSet.idToken ?? null,
    beforeSessionSaved
  );
  return sessionDataToStateData(finalized);
}

/**
 * Returns true when the IPSIE session ceiling has been reached.
 * Applies 30s negative leeway for clock skew — the session is treated as
 * expired slightly before the wall-clock ceiling, never after.
 * A missing/undefined value means no ceiling was asserted; returns false.
 */
export function isSessionCeilingReached(sessionExpiresAt?: number): boolean {
  if (sessionExpiresAt == null) return false;
  const now = Math.floor(Date.now() / 1000);
  return now >= sessionExpiresAt - SESSION_EXPIRY_LEEWAY_SECONDS;
}

/**
 * Returns true when the session ceiling is already in the past at login time.
 * Compares against the ID token `iat` claim (falls back to wall-clock now).
 * Used to reject an already-expired session before persisting it.
 * A missing/undefined ceiling returns false (safe default — no ceiling).
 */
export function isSessionCeilingInPast(
  sessionExpiresAt?: number,
  iat?: unknown
): boolean {
  if (sessionExpiresAt == null) return false;
  const reference =
    typeof iat === "number" ? iat : Math.floor(Date.now() / 1000);
  return sessionExpiresAt <= reference + SESSION_EXPIRY_LEEWAY_SECONDS;
}

/**
 * Merge an access token from a popup MFA callback into an existing session.
 *
 * Adds a new `AccessTokenSet` entry to `session.accessTokens[]` for the
 * popup's target audience. This preserves the user's existing MRRT tokens,
 * refresh token, and primary `tokenSet` — a fresh session would destroy them.
 *
 * Also updates `refreshToken` and `idToken`/`user` claims if new ones were
 * issued during the popup flow.
 *
 * **Why `requestedScope` uses `transactionState.scope`, not `oidcRes.scope`:**
 *
 * This is a deliberate design choice driven by MRRT scope accumulation.
 *
 * When the SDK requests a token for a specific audience, it sends the full
 * merged scope string from the global config (e.g. "oauth openid profile
 * email offline_access"). Auth0 returns only the scopes relevant to the
 * target audience (e.g. "openid" for an API token) — the OIDC scopes like
 * "profile" and "email" are filtered out because they don't apply to the
 * API audience. This is expected Auth0 behavior, not a permission denial.
 *
 * The SDK's `findAccessTokenSet()` (default `matchMode: "requestedScope"`)
 * checks whether the stored `requestedScope` is a superset of the lookup
 * scope. The lookup scope is computed from the same global config via
 * `getTokenSet() -> mergeScopes(getScopeForAudience(...))`. By storing
 * `transactionState.scope` (which originates from the same global config),
 * the cache key roundtrips exactly: the same scope string used to start
 * the auth flow is the same one used to look it up later.
 *
 * If `oidcRes.scope` were stored as `requestedScope` instead, the cache
 * lookup would break. `findAccessTokenSet` calls
 * `compareScopes(stored.requestedScope, lookupScope)` — checking whether
 * the stored value is a superset of the lookup value. With
 * `requestedScope = "openid"` (narrow, from oidcRes) and a lookup scope
 * of `"oauth openid profile email offline_access"` (wide, from global
 * config), the superset check fails: "openid" does not contain "oauth",
 * "profile", "email", or "offline_access". This cache miss triggers a
 * refresh grant, which re-triggers MFA policy — producing an
 * `mfa_required` error loop.
 *
 * Mutates `session` in-place. Caller is responsible for calling
 * `finalizeSession()` afterward.
 *
 * @param session - Existing user session loaded from cookie store
 * @param oidcRes - OAuth token response from the popup's code exchange
 * @param transactionState - Transaction state containing audience and scope
 * @param idTokenClaims - Validated ID token claims, if present in response
 */
export function mergePopupTokenIntoSession(
  session: SessionData,
  tokenResponse: TokenResponse,
  transactionState: TransactionState,
  idTokenClaims?: IdTokenClaims
): void {
  session.accessTokens = session.accessTokens || [];

  const newAccessTokenSet: AccessTokenSet = {
    accessToken: tokenResponse.accessToken,
    scope: tokenResponse.scope,
    requestedScope: transactionState.scope,
    audience: transactionState.audience || "",
    // The engine's `expiresAt` is already an absolute Unix timestamp (seconds),
    // so no `Date.now() + expires_in` computation is needed here.
    expiresAt: tokenResponse.expiresAt,
    token_type: tokenResponse.tokenType
  };

  // Replace existing token for same audience, or append new one.
  //
  // NOTE: This dedup keys on audience alone — differently-scoped tokens for
  // the same audience are evicted here. The MFA step-up dedup in
  // `cacheTokenFromMfaVerify` (auth-client.ts) uses a stricter audience+scope
  // key that preserves distinct-scope entries. Both rules are pre-existing on
  // main and ship side by side. Unifying them into one shared helper is a
  // separate refactor.
  const existingIdx = session.accessTokens.findIndex(
    (t) => t.audience === transactionState.audience
  );
  if (existingIdx >= 0) {
    session.accessTokens[existingIdx] = newAccessTokenSet;
  } else {
    session.accessTokens.push(newAccessTokenSet);
  }

  // Update refresh token if a new one was issued
  if (tokenResponse.refreshToken) {
    session.tokenSet.refreshToken = tokenResponse.refreshToken;
  }

  // Update id token and user claims if new ones were issued
  if (tokenResponse.idToken) {
    session.tokenSet.idToken = tokenResponse.idToken;
    if (idTokenClaims) {
      session.user = { ...session.user, ...idTokenClaims };
    }
  }
}

/**
 * Build a fresh SessionData from an OAuth token response and transaction state.
 * Used by both the postMessage fallback (no existing session) and the standard
 * redirect branch to avoid duplicating the same construction logic.
 *
 * @param idTokenClaims - Validated ID token claims (must be present)
 * @param tokenResponse - The engine's token response for the code exchange
 * @param transactionState - Transaction state with audience/scope
 * @returns A new SessionData object
 */
export function buildSessionFromCallback(
  idTokenClaims: IdTokenClaims,
  tokenResponse: TokenResponse,
  transactionState: TransactionState
): SessionData {
  // Reject non-positive values (0, negatives), millisecond timestamps (13+ digits),
  // NaN, Infinity, and non-numbers, all fall open to "no ceiling."
  const rawExpiry = idTokenClaims.session_expiry;
  const sessionExpiresAt =
    typeof rawExpiry === "number" && rawExpiry > 0 && rawExpiry < 10_000_000_000
      ? rawExpiry
      : undefined;

  return {
    user: idTokenClaims,
    tokenSet: {
      accessToken: tokenResponse.accessToken,
      idToken: tokenResponse.idToken,
      scope: tokenResponse.scope,
      requestedScope: transactionState.scope,
      audience: transactionState.audience,
      refreshToken: tokenResponse.refreshToken,
      // The engine's `expiresAt` is already an absolute Unix timestamp (seconds).
      expiresAt: tokenResponse.expiresAt
    },
    internal: {
      sid: idTokenClaims.sid as string,
      createdAt: Math.floor(Date.now() / 1000),
      ...(sessionExpiresAt !== undefined && { sessionExpiresAt })
    }
  };
}
