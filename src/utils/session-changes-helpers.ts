import { SessionData, TokenSet } from "../types/index.js";
import {
  accessTokenSetFromTokenSet,
  findAccessTokenSet
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
 * @param options Options containing the audience and scope for which the tokenSet was obtained
 * @param globalOptions The global audience and scope configured for the Auth0Client
 * @returns Partial session changes or undefined if no changes are needed
 */
export function getSessionChangesAfterGetAccessToken(
  session: SessionData,
  tokenSet: TokenSet,
  options: { scope?: string | null; audience?: string | null },
  globalOptions: {
    scope?: string | null | undefined;
    audience?: string | null | undefined;
  }
): Partial<SessionData> | undefined {
  const isAudienceTheGlobalAudience =
    !options.audience || options.audience === globalOptions.audience;
  const isScopeTheGlobalScope =
    !options.scope || options.scope === globalOptions.scope;

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
  const audience = options.audience ?? globalOptions.audience;
  const scope = options.scope ?? globalOptions.scope ?? undefined;

  // If there is no audience, we cannot find the correct access token in the array
  if (!audience) {
    return;
  }

  const existingAccessTokenSet = findAccessTokenSet(session, {
    scope,
    audience
  });

  let sessionChanges: Pick<SessionData, "accessTokens"> | undefined = undefined;

  if (!existingAccessTokenSet) {
    // There is no access token found matches the provided `audience` and `scope`.
    // We need to add a new entry to the array.
    sessionChanges = {
      accessTokens: [
        ...(session.accessTokens || []),
        accessTokenSetFromTokenSet(tokenSet, { audience })
      ]
    };
  } else {
    // There is an existing access token for the provided `audience` and `scope`.
    // We need to check if the access token changed, and if so, update it in the array.
    if (tokenSet.accessToken !== existingAccessTokenSet.accessToken) {
      sessionChanges = {
        accessTokens: session.accessTokens?.map((accessToken) =>
          accessToken === existingAccessTokenSet
            ? accessTokenSetFromTokenSet(tokenSet, { audience })
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
