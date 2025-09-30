import { SessionData, TokenSet } from "../types/index.js";
import { getScopeForAudience } from "./scope-helpers.js";
import {
  accessTokenSetFromTokenSet,
  compareScopes,
  findAccessTokenSet,
  mergeScopes
} from "./token-set-helpers.js";

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
  }
): Partial<SessionData> | undefined {
  // Since globalOptions.scope can be a map of audience to scopes, we need to get the correct scope for the current audience.
  const globalScope = getScopeForAudience(
    globalOptions.scope,
    tokenSet.audience ?? globalOptions.audience
  );
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

  // If we are using the global audience and scope, we need to check if the access token or refresh token changed in `SessionData.tokenSet`.
  // We do not have to change anything to the `accessTokens` array inside `SessionData` in this case, so we can just return.
  if (isAudienceTheGlobalAudience && isScopeTheGlobalScope) {
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
    return;
  }

  // If we aren't using the global audience and scope,
  // we need to check if the corresponding access token changed in `SessionData.accessTokens`.
  // We will also have to update the refreshToken and idToken as needed
  const audience = tokenSet.audience ?? globalOptions.audience;
  const scope = tokenSet.requestedScope ?? globalScope ?? undefined;

  // If there is no audience, we cannot find the correct access token in the array
  if (!audience) {
    return;
  }

  // This finds the entry where we have a match based on the requestedScope.
  let existingAccessTokenSet = findAccessTokenSet(session, {
    scope,
    audience,
    matchMode: "requestedScope"
  });

  let sessionChanges: Pick<SessionData, "accessTokens"> | undefined = undefined;

  if (!existingAccessTokenSet) {
    // If there is no specific match based on the requestedScope, we may want to see if there is a match based on the actual scope retrieved.
    // If that is the case, we need to store them together:
    // - When the cache has an entry with scope "a" and requestedScope "a b"
    // - and we request a new token with requestedScope "a c" for the same audience, resulting in scope "a"
    // - we want to update the existing entry to have a requested scope of "a b c".
    //
    // This avoids having multiple entries for the same provided scope, which would lead to unnecessary token requests.
    // This also ensure, next time around when we request a token of scope "a b" or "a c", we will find the same existing entry in the cache, with provided scope set to "a".
    existingAccessTokenSet = findAccessTokenSet(
      session,
      {
        scope: tokenSet.scope,
        audience,
        matchMode: "scope"
      }
    );

    if (existingAccessTokenSet) {
      // We need to update the requestedScope to be a combination of both matches
      sessionChanges = {
        accessTokens: session.accessTokens?.map((accessToken) =>
          accessToken === existingAccessTokenSet
            ? accessTokenSetFromTokenSet(
                {
                  ...tokenSet,
                  requestedScope: mergeScopes(
                    accessToken.requestedScope,
                    tokenSet.requestedScope
                  )
                },
                { audience }
              )
            : accessToken
        )
      };
    } else {
      // There is no access token found matches the provided `audience` and `scope`.
      // We need to add a new entry to the array.
      sessionChanges = {
        accessTokens: [
          ...(session.accessTokens || []),
          accessTokenSetFromTokenSet(tokenSet, { audience })
        ]
      };
    }
  } else {
    // There is an existing access token for the provided `audience` and `scope`.
    // We need to check if the access token changed, and if so, update it in the array.
    if (tokenSet.accessToken !== existingAccessTokenSet.accessToken) {
      sessionChanges = {
        accessTokens: session.accessTokens?.map((accessToken) =>
          accessToken === existingAccessTokenSet
            ? accessTokenSetFromTokenSet(
                {
                  ...tokenSet,
                },
                { audience }
              )
            : accessToken
        )
      };
    }
  }

  // If there are no session changes, we can exit early.
  if (sessionChanges) {
    return {
      accessTokens: sessionChanges.accessTokens,
      tokenSet: {
        ...session.tokenSet,
        idToken: tokenSet.idToken,
        refreshToken: tokenSet.refreshToken
      }
    };
  }
}
