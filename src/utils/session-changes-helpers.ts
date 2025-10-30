import { AccessTokenSet, SessionData, TokenSet } from "../types/index.js";
import { getScopeForAudience } from "./scope-helpers.js";
import {
  accessTokenSetFromTokenSet,
  compareScopes,
  findAccessTokenSet,
  mergeScopes
} from "./token-set-helpers.js";

/**
 * Checks if a tokenSet represents global audience and scope configuration.
 * @param tokenSet The token set to check
 * @param session The current session data
 * @param globalScope The global scope configuration
 * @param globalOptions The global options containing audience configuration
 * @returns True if the tokenSet uses global audience and scope, false otherwise
 */
function isGlobalAudienceAndScope(
  tokenSet: TokenSet,
  session: SessionData,
  globalScope: string | undefined,
  globalOptions: {
    audience?: string | null | undefined;
  }
): boolean {
  const isAudienceTheGlobalAudience =
    !tokenSet.audience ||
    tokenSet.audience === (session.tokenSet.audience ?? globalOptions.audience);

  const isScopeTheGlobalScope =
    !tokenSet.requestedScope ||
    // Compare against either the initially requested scope, or the global scope if no requested scope is set.
    // Typically, the requestedScope should always be set, but in case of legacy sessions it might not be so we need to fall-back
    // to the global scope if that is the case.
    compareScopes(
      session.tokenSet.requestedScope ?? globalScope,
      tokenSet.requestedScope
    );

  return isAudienceTheGlobalAudience && isScopeTheGlobalScope;
}

/**
 * Handles updates to the global tokenSet when the new token uses global audience and scope.
 * @param tokenSet The new token set to potentially update with
 * @param session The current session data
 * @returns Partial session data with updated tokenSet, or undefined if no changes needed
 */
function handleGlobalTokenSetUpdate(
  tokenSet: TokenSet,
  session: SessionData
): Partial<SessionData> | undefined {
  if (
    tokenSet.accessToken !== session.tokenSet.accessToken ||
    tokenSet.expiresAt !== session.tokenSet.expiresAt ||
    tokenSet.refreshToken !== session.tokenSet.refreshToken
  ) {
    return {
      tokenSet
    };
  }

  // When we use the global audience and scope, and nothing changed, we can exit early.
  return undefined;
}

/**
 * Updates an existing access token set with merged requested scopes.
 *
 * IMPORTANT: This function merges the requestedScope fields from both the existing
 * and new token sets. The actual granted scopes (tokenSet.scope) come from the
 * authorization server and represent what was actually granted for this specific request.
 * We track both values to:
 * 1. Know what scopes were originally requested (requestedScope)
 * 2. Know what scopes were actually granted (scope)
 *
 * The merged requestedScope should never grant more permissions than what the
 * authorization server would allow - it only tracks what has been requested across
 * multiple token requests for the same audience. The actual permissions are always
 * determined by the authorization server's response (tokenSet.scope).
 *
 * @param session The current session data
 * @param tokenSet The new token set with updated scopes from the authorization server
 * @param existingAccessTokenSet The existing access token set to update
 * @param audience The audience for the access token
 * @returns Updated session data with merged requested scopes but actual granted scopes from tokenSet
 */
function updateExistingAccessTokenWithMergedRequestedScopes(
  session: SessionData,
  tokenSet: TokenSet,
  existingAccessTokenSet: AccessTokenSet,
  audience: string
): Pick<SessionData, "accessTokens"> {
  return {
    accessTokens: session.accessTokens?.map((accessToken) =>
      accessToken === existingAccessTokenSet
        ? accessTokenSetFromTokenSet(
            {
              ...tokenSet,
              // Use the merged requested scopes (of both existing and new entry) for lookup purposes
              requestedScope: mergeScopes(
                accessToken.requestedScope,
                tokenSet.requestedScope
              ),
              // Use the actual granted scope from the authorization server
              scope: tokenSet.scope
            },
            { audience }
          )
        : accessToken
    )
  };
}

/**
 * Adds a new access token set to the session's accessTokens array.
 * @param session The current session data
 * @param tokenSet The token set to add as a new access token
 * @param audience The audience for the new access token
 * @returns Updated session data with the new access token added
 */
function addNewAccessTokenSet(
  session: SessionData,
  tokenSet: TokenSet,
  audience: string
): Pick<SessionData, "accessTokens"> {
  return {
    accessTokens: [
      ...(session.accessTokens || []),
      accessTokenSetFromTokenSet(tokenSet, { audience })
    ]
  };
}

/**
 * Updates an existing access token set if the access token has changed.
 * @param session The current session data
 * @param tokenSet The new token set with potentially updated access token
 * @param existingAccessTokenSet The existing access token set to compare against
 * @param audience The audience for the access token
 * @returns Updated session data if access token changed, undefined otherwise
 */
function updateExistingAccessTokenSet(
  session: SessionData,
  tokenSet: TokenSet,
  existingAccessTokenSet: AccessTokenSet,
  audience: string
): Pick<SessionData, "accessTokens"> | undefined {
  if (tokenSet.accessToken !== existingAccessTokenSet.accessToken) {
    return {
      accessTokens: session.accessTokens?.map((accessToken) =>
        accessToken === existingAccessTokenSet
          ? accessTokenSetFromTokenSet(tokenSet, { audience })
          : accessToken
      )
    };
  }
  return undefined;
}

/**
 * Handles updates to specific access tokens for non-global audience/scope combinations.
 * @param session The current session data
 * @param tokenSet The new token set to process
 * @param audience The specific audience for the access token
 * @param scope The specific scope for the access token
 * @returns Partial session data with access token updates, or undefined if no changes needed
 */
function handleSpecificAccessTokenUpdate(
  session: SessionData,
  tokenSet: TokenSet,
  audience: string,
  scope: string | undefined,
  progressiveScopes: boolean
): Partial<SessionData> | undefined {
  // First, try to find an entry based on the requestedScope
  let existingAccessTokenSet = findAccessTokenSet(session, {
    scope,
    audience,
    matchMode: "requestedScope",
    progressiveScopes
  });

  if (!existingAccessTokenSet) {
    // If there is no specific match based on the requestedScope, we may want to see if there is a match based on the actual scope retrieved.
    // If that is the case, we need to store them together:
    // - When the cache has an entry with scope "a" and requestedScope "a b"
    // - and we request a new token with requestedScope "a c" for the same audience, resulting in scope "a"
    // - we want to update the existing entry to have a requested scope of "a b c".
    //
    // This avoids having multiple entries for the same provided scope, which would lead to unnecessary token requests.
    // This also ensure, next time around when we request a token of scope "a b" or "a c", we will find the same existing entry in the cache, with provided scope set to "a".
    existingAccessTokenSet = findAccessTokenSet(session, {
      scope: tokenSet.scope,
      audience,
      matchMode: "scope",
      progressiveScopes
    });

    if (existingAccessTokenSet) {
      // We need to update the requestedScope to be a combination of both matches
      const accessTokenChanges =
        updateExistingAccessTokenWithMergedRequestedScopes(
          session,
          tokenSet,
          existingAccessTokenSet,
          audience
        );
      return buildSessionChanges(session, tokenSet, accessTokenChanges);
    } else {
      // There is no access token found that matches the provided `audience` and `scope`.
      // We need to add a new entry to the array.
      const accessTokenChanges = addNewAccessTokenSet(
        session,
        tokenSet,
        audience
      );
      return buildSessionChanges(session, tokenSet, accessTokenChanges);
    }
  } else {
    // There is an existing access token for the provided `audience` and `scope`.
    // We need to check if the access token changed, and if so, update it in the array.
    const accessTokenChanges = updateExistingAccessTokenSet(
      session,
      tokenSet,
      existingAccessTokenSet,
      audience
    );
    return buildSessionChanges(session, tokenSet, accessTokenChanges);
  }
}

/**
 * Builds the final session changes object with both accessTokens and tokenSet updates.
 * @param session The current session data
 * @param tokenSet The new token set containing idToken and refreshToken updates
 * @param accessTokenChanges The access token changes to merge into the final result
 * @returns Complete session changes with both access tokens and token set updates, or undefined if no changes
 */
function buildSessionChanges(
  session: SessionData,
  tokenSet: TokenSet,
  accessTokenChanges: Pick<SessionData, "accessTokens"> | undefined
): Partial<SessionData> | undefined {
  if (accessTokenChanges) {
    return {
      accessTokens: accessTokenChanges.accessTokens,
      tokenSet: {
        ...session.tokenSet,
        idToken: tokenSet.idToken,
        refreshToken: tokenSet.refreshToken
      }
    };
  }
  return undefined;
}

/**
 * Determines the necessary changes to the session after obtaining a new access token.
 *
 * This function checks if the provided tokenSet corresponds to the global audience and scope
 * or a specific one. It then determines if any updates are needed in the session's tokenSet
 * or accessTokens array and returns the required changes.
 *
 * If no changes are needed, it returns undefined.
 * @param session The original session data
 * @param tokenSet The, potentially, new TokenSet obtained
 * @param globalOptions The global audience and scope configured for the Auth0Client
 * @returns Partial session changes or undefined if no changes are needed
 */
export function getSessionChangesAfterGetAccessToken(
  session: SessionData,
  tokenSet: TokenSet,
  globalOptions: {
    scope?: string | null | undefined | { [key: string]: string };
    audience?: string | null | undefined;
  },
  progressiveScopes: boolean
): Partial<SessionData> | undefined {
  // Since globalOptions.scope can be a map of audience to scopes, we need to get the correct scope for the current audience.
  const globalScope = getScopeForAudience(
    globalOptions.scope,
    tokenSet.audience ?? globalOptions.audience
  );

  // If we are using the global audience and scope, we need to check if the access token or refresh token changed in `SessionData.tokenSet`.
  // We do not have to change anything to the `accessTokens` array inside `SessionData` in this case, so we can just return.
  if (isGlobalAudienceAndScope(tokenSet, session, globalScope, globalOptions)) {
    return handleGlobalTokenSetUpdate(tokenSet, session);
  }

  // If we aren't using the global audience and scope,
  // we need to check if the corresponding access token changed in `SessionData.accessTokens`.
  // We will also have to update the refreshToken and idToken as needed
  const audience = tokenSet.audience ?? globalOptions.audience;
  const scope = tokenSet.requestedScope ?? globalScope ?? undefined;

  // If there is no audience, we cannot find the correct access token in the array
  if (!audience) {
    return undefined;
  }

  return handleSpecificAccessTokenUpdate(session, tokenSet, audience, scope, progressiveScopes);
}
