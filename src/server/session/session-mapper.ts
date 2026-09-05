import type { StateData } from "@auth0/auth0-server-js";

import type {
  AccessTokenSet,
  ConnectionTokenSet,
  SessionData,
  TokenSet
} from "../../types/index.js";
import type { MCDMetadata } from "../../types/mcd.js";

// auth0-server-js's TokenSet is { audience, accessToken, scope, expiresAt }.
// nextjs-auth0 stores requestedScope and token_type alongside each token.
// These extra fields survive the encrypted JSON round-trip even though
// auth0-server-js's TypeScript type doesn't declare them.
interface ExtendedTokenSet {
  audience: string;
  accessToken: string;
  scope: string | undefined;
  expiresAt: number;
  requestedScope?: string;
  token_type?: string;
}

export function sessionDataToStateData(session: SessionData): StateData {
  const primaryTs: ExtendedTokenSet = {
    audience: session.tokenSet.audience ?? "",
    accessToken: session.tokenSet.accessToken,
    scope: session.tokenSet.scope,
    expiresAt: session.tokenSet.expiresAt,
    ...(session.tokenSet.requestedScope !== undefined && {
      requestedScope: session.tokenSet.requestedScope
    }),
    ...(session.tokenSet.token_type !== undefined && {
      token_type: session.tokenSet.token_type
    })
  };

  const additionalTs: ExtendedTokenSet[] = (session.accessTokens ?? []).map(
    (at: AccessTokenSet): ExtendedTokenSet => ({
      audience: at.audience,
      accessToken: at.accessToken,
      scope: at.scope,
      expiresAt: at.expiresAt,
      ...(at.requestedScope !== undefined && {
        requestedScope: at.requestedScope
      }),
      ...(at.token_type !== undefined && { token_type: at.token_type })
    })
  );

  return {
    user: session.user,
    idToken: session.tokenSet.idToken,
    refreshToken: session.tokenSet.refreshToken,
    tokenSets: [primaryTs, ...additionalTs] as StateData["tokenSets"],
    ...(session.internal.sessionExpiresAt !== undefined && {
      sessionExpiresAt: session.internal.sessionExpiresAt
    }),
    ...(session.internal.mcd !== undefined && { mcd: session.internal.mcd }),
    // Connection token sets are a nextjs-auth0 concept the engine's `StateData`
    // does not declare. In STATEFUL mode they live inside the persisted row, so
    // they must round-trip through the mapper (like `mcd`) or slice 3 writes
    // would drop them. In STATELESS mode they live in separate `__FC_*` cookies
    // and never reach here, so this is a no-op for stateless.
    ...(session.connectionTokenSets !== undefined && {
      // nextjs-auth0's `ConnectionTokenSet` (scope optional) is structurally
      // carried through the engine's `StateData.connectionTokenSets` (scope
      // required); the value is opaque pass-through, cast across the boundary.
      connectionTokenSets:
        session.connectionTokenSets as StateData["connectionTokenSets"]
    }),
    internal: {
      sid: session.internal.sid,
      createdAt: session.internal.createdAt
    }
  };
}

export function stateDataToSessionData(
  state: StateData
): SessionData | undefined {
  if (!state.tokenSets?.length || !state.user) {
    return undefined;
  }

  const [primaryTs, ...additionalTs] = state.tokenSets as ExtendedTokenSet[];

  const tokenSet: TokenSet = {
    accessToken: primaryTs.accessToken,
    scope: primaryTs.scope,
    expiresAt: primaryTs.expiresAt,
    audience: primaryTs.audience || undefined,
    idToken: state.idToken ?? undefined,
    refreshToken: state.refreshToken ?? undefined,
    ...(primaryTs.requestedScope !== undefined && {
      requestedScope: primaryTs.requestedScope
    }),
    ...(primaryTs.token_type !== undefined && {
      token_type: primaryTs.token_type
    })
  };

  const accessTokens: AccessTokenSet[] | undefined = additionalTs.length
    ? additionalTs.map((ts): AccessTokenSet => ({
        audience: ts.audience,
        accessToken: ts.accessToken,
        scope: ts.scope,
        expiresAt: ts.expiresAt,
        ...(ts.requestedScope !== undefined && {
          requestedScope: ts.requestedScope
        }),
        ...(ts.token_type !== undefined && { token_type: ts.token_type })
      }))
    : undefined;

  // Native format stores sessionExpiresAt at top-level; v4 stored it inside internal.
  const sessionExpiresAt =
    state.sessionExpiresAt ??
    (state.internal as unknown as { sessionExpiresAt?: number })
      .sessionExpiresAt;

  const mcd = (state as unknown as { mcd?: MCDMetadata }).mcd;

  // Restore the stateful pass-through connection token sets (see
  // `sessionDataToStateData`). Undefined in stateless mode.
  const connectionTokenSets = (
    state as unknown as { connectionTokenSets?: ConnectionTokenSet[] }
  ).connectionTokenSets;

  return {
    user: state.user as SessionData["user"],
    tokenSet,
    ...(accessTokens && { accessTokens }),
    ...(connectionTokenSets && { connectionTokenSets }),
    internal: {
      sid: state.internal.sid,
      createdAt: state.internal.createdAt,
      ...(sessionExpiresAt !== undefined && { sessionExpiresAt }),
      ...(mcd !== undefined && { mcd })
    }
  };
}
