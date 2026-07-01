import * as oauth from "oauth4webapi";

import { TransactionState } from "../server/transaction-store.js";
import type { AccessTokenSet, SessionData } from "../types/index.js";

const SESSION_EXPIRY_LEEWAY_SECONDS = 30;

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
  oidcRes: oauth.TokenEndpointResponse,
  transactionState: TransactionState,
  idTokenClaims?: oauth.IDToken
): void {
  session.accessTokens = session.accessTokens || [];

  const newAccessTokenSet: AccessTokenSet = {
    accessToken: oidcRes.access_token,
    scope: oidcRes.scope,
    requestedScope: transactionState.scope,
    audience: transactionState.audience || "",
    expiresAt: Math.floor(Date.now() / 1000) + Number(oidcRes.expires_in),
    token_type: oidcRes.token_type
  };

  // Replace existing token for same audience, or append new one
  const existingIdx = session.accessTokens.findIndex(
    (t) => t.audience === transactionState.audience
  );
  if (existingIdx >= 0) {
    session.accessTokens[existingIdx] = newAccessTokenSet;
  } else {
    session.accessTokens.push(newAccessTokenSet);
  }

  // Update refresh token if a new one was issued
  if (oidcRes.refresh_token) {
    session.tokenSet.refreshToken = oidcRes.refresh_token;
  }

  // Update id token and user claims if new ones were issued
  if (oidcRes.id_token) {
    session.tokenSet.idToken = oidcRes.id_token;
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
 * @param oidcRes - OAuth token endpoint response
 * @param transactionState - Transaction state with audience/scope
 * @returns A new SessionData object
 */
export function buildSessionFromCallback(
  idTokenClaims: oauth.IDToken,
  oidcRes: oauth.TokenEndpointResponse,
  transactionState: TransactionState
): SessionData {
  // Reject non-positive values (0, negatives), millisecond timestamps (13+ digits),
  // NaN, Infinity, and non-numbers — all fall open to "no ceiling."
  const rawExpiry = idTokenClaims.session_expiry;
  const sessionExpiresAt =
    typeof rawExpiry === "number" && rawExpiry > 0 && rawExpiry < 10_000_000_000
      ? rawExpiry
      : undefined;

  return {
    user: idTokenClaims,
    tokenSet: {
      accessToken: oidcRes.access_token,
      idToken: oidcRes.id_token,
      scope: oidcRes.scope,
      requestedScope: transactionState.scope,
      audience: transactionState.audience,
      refreshToken: oidcRes.refresh_token,
      expiresAt: Math.floor(Date.now() / 1000) + Number(oidcRes.expires_in)
    },
    internal: {
      sid: idTokenClaims.sid as string,
      createdAt: Math.floor(Date.now() / 1000),
      ...(sessionExpiresAt !== undefined && { sessionExpiresAt })
    }
  };
}
