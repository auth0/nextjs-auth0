import type {
  TokenSet as EngineTokenSet,
  StateData
} from "@auth0/auth0-server-js";

import type {
  AccessTokenSet,
  SessionData,
  TokenSet,
  User
} from "../../types/index.js";

// The engine's cache key for "no specific audience" (engine `getAccessToken`). Never sent.
const ENGINE_DEFAULT_AUDIENCE = "default";

export interface SessionMapperOptions {
  /**
   * `authorizationParameters.audience`, the same value given to the engine.
   */
  audience?: string;
}

export interface SessionMapper {
  toStateData(session: SessionData): StateData;
  toSessionData(stateData: StateData): SessionData;
}

/**
 * Converts between today's `SessionData` (the public shape: `getSession()`, `updateSession()`,
 * hooks, `SessionDataStore` rows) and the engine's `StateData` (used everywhere inside).
 *
 * Only fields whose place differs are moved. Every other field, on the session, in `internal`
 * and on each token entry, passes through untouched in both directions, so custom fields and
 * fields the engine adds later survive. A custom field named like a field of the other shape is
 * dropped, so it is never taken for the real value.
 */
export function createSessionMapper({
  audience
}: SessionMapperOptions): SessionMapper {
  // The key the engine files and looks up the login token under.
  const defaultAudienceKey = audience ?? ENGINE_DEFAULT_AUDIENCE;

  function toStateData(session: SessionData): StateData {
    const {
      user,
      tokenSet,
      accessTokens,
      connectionTokenSets,
      internal,
      // Engine field names: dropped when used as custom fields.
      idToken: _idToken,
      refreshToken: _refreshToken,
      tokenSets: _tokenSets,
      domain: _domain,
      sessionExpiresAt: _sessionExpiresAt,
      ...rest
    } = session;
    const { idToken, refreshToken, ...primary } = tokenSet;
    const { mcd, sessionExpiresAt, ...internalRest } = internal;

    // Today's login writes no audience on the primary token; file it under the engine's key so
    // the engine finds it (`||`, as in `main`'s rule). Entries keep fields the engine does not
    // read (`requestedScope`, `token_type`); the engine type has no index signature.
    const tokenSets = [
      { ...primary, audience: primary.audience || defaultAudienceKey },
      ...(accessTokens ?? [])
    ] as EngineTokenSet[];

    return {
      ...rest,
      user,
      idToken,
      refreshToken,
      tokenSets,
      ...(connectionTokenSets && {
        // Same fields; today's `scope` is optional, the engine's is `string | undefined`.
        connectionTokenSets:
          connectionTokenSets as StateData["connectionTokenSets"]
      }),
      ...(mcd?.domain && { domain: mcd.domain }),
      ...(sessionExpiresAt !== undefined && { sessionExpiresAt }),
      internal: internalRest
    };
  }

  function toSessionData(stateData: StateData): SessionData {
    const {
      user,
      idToken,
      refreshToken,
      tokenSets,
      connectionTokenSets,
      domain,
      sessionExpiresAt,
      internal,
      // Today's field names: dropped when used as custom fields.
      tokenSet: _tokenSet,
      accessTokens: _accessTokens,
      ...rest
    } = stateData;
    const {
      mcd: _mcd,
      sessionExpiresAt: _internalSessionExpiresAt,
      ...internalRest
    } = internal as SessionData["internal"];

    const entries = tokenSets ?? [];
    const defaultIndex = entries.findIndex(
      (entry) => entry.audience === defaultAudienceKey
    );
    const primaryIndex = defaultIndex === -1 ? 0 : defaultIndex;
    const primary = entries[primaryIndex];
    const others = entries.filter((_, i) => i !== primaryIndex);

    let tokenSet: TokenSet;
    if (primary) {
      // The engine's key goes back to "no audience", as today's login writes it.
      const { audience: primaryAudience, ...primaryRest } = primary;
      tokenSet = {
        ...primaryRest,
        ...(primaryAudience !== defaultAudienceKey && {
          audience: primaryAudience
        })
      } as TokenSet;
    } else {
      // No entries (not reached by normal logins): an already-expired placeholder, so the
      // session is kept and the engine refreshes when asked.
      tokenSet = { accessToken: "", expiresAt: 0 };
    }
    if (idToken !== undefined) tokenSet.idToken = idToken;
    if (refreshToken !== undefined) tokenSet.refreshToken = refreshToken;

    return {
      ...rest,
      user: (user ?? {}) as User,
      tokenSet,
      ...(others.length > 0 && { accessTokens: others as AccessTokenSet[] }),
      ...(connectionTokenSets && {
        connectionTokenSets:
          connectionTokenSets as SessionData["connectionTokenSets"]
      }),
      internal: {
        ...internalRest,
        ...(sessionExpiresAt !== undefined && { sessionExpiresAt }),
        // The engine stores the domain as a bare host; on Auth0 the issuer is always
        // `https://{domain}/`, as `main` fills it for sessions without `mcd`.
        ...(domain && { mcd: { domain, issuer: `https://${domain}/` } })
      }
    };
  }

  return { toStateData, toSessionData };
}
