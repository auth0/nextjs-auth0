import { AccessTokenSet, SessionData, TokenSet } from "../types/index.js";

/**
 * Converts a TokenSet to an AccessTokenSet, including optional audience and scope.
 * @param tokenSet the TokenSet to convert
 * @param options object containing optional audience and scope
 * @returns AccessTokenSet
 */
export function accessTokenSetFromTokenSet(
  tokenSet: TokenSet,
  options: { audience: string; scope?: string }
): AccessTokenSet {
  return {
    accessToken: tokenSet.accessToken,
    expiresAt: tokenSet.expiresAt,
    audience: options.audience,
    scope: options.scope
  };
}

/**
 * Parses a scope string into an array of individual scopes, filtering out empty strings.
 * @param scopes Space-separated scope string
 * @returns Array of scope strings
 */
function parseScopesToArray(scopes: string | undefined): string[] {
  if (!scopes) return [];
  return scopes.trim().split(" ").filter(Boolean);
}

/**
 * Compares two sets of scopes to determine if all required scopes are present in the provided scopes.
 * @param scopes Scopes to compare (space-separated string)
 * @param requiredScopes Scopes required to be present in the scopes (space-separated string)
 * @returns True if all required scopes are present in the scopes, false otherwise
 */
export const compareScopes = (
  scopes: string | undefined,
  requiredScopes: string | undefined
): boolean => {
  // When the scopes and requiredScopes are exactly the same, return true
  // This handles cases where both are empty or undefined or both are the same string
  if (scopes === requiredScopes) {
    return true;
  }

  if (!scopes || !requiredScopes) {
    return false;
  }

  const scopesSet = new Set(parseScopesToArray(scopes));
  const requiredScopesArray = parseScopesToArray(requiredScopes);

  return requiredScopesArray.every((scope) => scopesSet.has(scope));
};

/**
 * Finds the best matching AccessTokenSet in the session by audience and scope.
 *
 * The function determines a "match" if an AccessTokenSet's scope property contains all the items
 * from the `options.scope`. From the potential matches, it selects the best one
 * based on the following criteria, in order of priority:
 *
 * 1. An "exact match" is preferred above all. This is where the AccessTokenSet's scope
 *    has the exact same items as the `options.scope` (length and content are identical,
 *    order does not matter).
 * 2. If no exact match is found, the "best partial match" is chosen. This is the
 *    matching AccessTokenSet whose scope has the fewest additional items.
 *
 * @param sessionData The session data containing accessTokens array.
 * @param options Object containing the scope and audience to match against.
 * @returns The best matching AccessTokenSet, or undefined if no match is found.
 */
export function findAccessTokenSet(
  sessionData: SessionData | undefined,
  options: {
    scope?: string;
    audience: string;
  }
): AccessTokenSet | undefined {
  const accessTokenSets = sessionData?.accessTokens;

  // 1. When there are no access tokens, we can exit early.
  if (!accessTokenSets || accessTokenSets.length === 0) {
    return;
  }

  // 2. Filter the list to find all AccessTokenSet's that are valid matches.
  // A valid match's audience must match the provided `options.audience`,
  // and its scope must contain all items from `options.scope`.
  const allMatches = accessTokenSets.filter((accessTokenSet) => {
    return (
      accessTokenSet.audience === options.audience &&
      compareScopes(accessTokenSet.scope, options.scope)
    );
  });

  // If no potential matches were found, we can exit early.
  if (allMatches.length === 0) {
    return;
  }

  // 3. Sort the valid matches to find the best one.
  // The best match is the one with the smallest scope array, as it has the fewest
  // extra permissions. An exact match will naturally be sorted first.
  // This also works for null/undefined scopes, as they would have been matched
  // against a null/undefined `options.scope` and will all be equally valid.
  allMatches.sort((a, b) => {
    const aScopeCount = parseScopesToArray(a.scope).length;
    const bScopeCount = parseScopesToArray(b.scope).length;
    return aScopeCount - bScopeCount;
  });

  // The first item in the sorted list is the best possible match.
  return allMatches[0];
}
