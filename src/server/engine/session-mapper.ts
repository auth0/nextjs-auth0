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
export const ENGINE_DEFAULT_AUDIENCE = "default";

export interface SessionMapperOptions {
  /**
   * `authorizationParameters.audience`, the same value given to the engine.
   */
  audience?: string;
}

export interface SessionMapper {
  toStateData(session: SessionData): StateData;
  toSessionData(stateData: StateData): SessionData;
  /**
   * The audience the engine files the login token under: the configured one, else its own key.
   */
  defaultAudienceKey: string;
}

type TokenEntry = Record<string, unknown>;

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
    // nextjs saves a session without `tokenSet`, so one can be stored; it becomes no entries.
    const { idToken, refreshToken, ...primary } = (tokenSet ?? {}) as TokenSet;
    const { mcd, sessionExpiresAt, ...internalRest } = internal;

    // A primary token without an audience is filed under the engine's key so the engine finds it
    // (`||`, as in nextjs's rule). Entries keep fields the engine does not read; the engine type
    // has no index signature.
    const tokenSets = [
      ...(tokenSet
        ? [{ ...primary, audience: primary.audience || defaultAudienceKey }]
        : []),
      ...(accessTokens ?? [])
    ].map((entry) =>
      toEngineEntry(entry as unknown as TokenEntry)
    ) as unknown as EngineTokenSet[];

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

    const entries = (tokenSets ?? []).map(
      (entry) =>
        toSessionEntry(
          entry as unknown as TokenEntry
        ) as unknown as EngineTokenSet
    );
    // The login token stays the primary one, as on nextjs: it is the first entry, and a token
    // requested later is appended.
    const [primary, ...others] = entries;

    let tokenSet: TokenSet;
    if (primary) {
      // Only the engine's own placeholder goes back to "no audience"; a configured or per-login
      // audience is kept, as today's login writes it.
      const { audience: primaryAudience, ...primaryRest } = primary;
      tokenSet = {
        ...primaryRest,
        ...(primaryAudience !== ENGINE_DEFAULT_AUDIENCE && {
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
        // `https://{domain}/`, as nextjs fills it for sessions without `mcd`.
        ...(domain && { mcd: { domain, issuer: `https://${domain}/` } })
      }
    };
  }

  return { toStateData, toSessionData, defaultAudienceKey };
}

/**
 * Today's `token_type` on a token entry is the engine's `tokenType`.
 */
function toEngineEntry(entry: TokenEntry): TokenEntry {
  const { token_type, tokenType: _tokenType, ...rest } = entry;
  return {
    ...rest,
    ...(token_type !== undefined && { tokenType: token_type })
  };
}

function toSessionEntry(entry: TokenEntry): TokenEntry {
  const { tokenType, token_type: _tokenType, ...rest } = entry;
  return {
    ...rest,
    ...(tokenType !== undefined && { token_type: tokenType })
  };
}
