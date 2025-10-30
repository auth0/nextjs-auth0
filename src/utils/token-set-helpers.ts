import { AccessTokenSet, SessionData, TokenSet } from "../types/index.js";

/**
 * Converts a TokenSet to an AccessTokenSet, including optional audience and scope.
 * @param tokenSet the TokenSet to convert
 * @param options object containing optional audience
 * @returns AccessTokenSet
 */
export function accessTokenSetFromTokenSet(
  tokenSet: TokenSet,
  options: { audience: string }
): AccessTokenSet {
  return {
    accessToken: tokenSet.accessToken,
    expiresAt: tokenSet.expiresAt,
    audience: options.audience,
    scope: tokenSet.scope,
    requestedScope: tokenSet.requestedScope,
    ...(tokenSet.token_type && { token_type: tokenSet.token_type })
  };
}

/**
 * Converts an AccessTokenSet and a partial TokenSet into a partial TokenSet.
 * This is useful for merging an AccessTokenSet back into a TokenSet structure,
 * while preserving other properties of the TokenSet.
 * @param accessTokenSet the AccessTokenSet to convert
 * @param tokenSet the partial TokenSet to merge with
 * @returns The merged partial TokenSet
 */
export function tokenSetFromAccessTokenSet(
  accessTokenSet: AccessTokenSet | undefined,
  tokenSet: Partial<TokenSet>
): Partial<TokenSet> {
  return {
    ...tokenSet,
    accessToken: accessTokenSet?.accessToken,
    expiresAt: accessTokenSet?.expiresAt,
    scope: accessTokenSet?.scope,
    requestedScope: accessTokenSet?.requestedScope,
    audience: accessTokenSet?.audience,
    ...(accessTokenSet?.token_type && { token_type: accessTokenSet.token_type }),
    scopeMetadata: accessTokenSet?.scopeMetadata
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
 * @param options Optional settings for comparison
 * @param options.strict If true, requires an exact match of scopes (no extra scopes allowed)
 * @returns True if all required scopes are present in the scopes, false otherwise
 */
export const compareScopes = (
  scopes: string | null | undefined,
  requiredScopes: string | undefined,
  options: { strict?: boolean } = {}
): boolean => {
  // When the scopes and requiredScopes are exactly the same, return true
  if (scopes === requiredScopes) {
    return true;
  }

  if (!scopes || !requiredScopes) {
    return false;
  }

  const scopesSet = new Set(parseScopesToArray(scopes));
  const requiredScopesSet = new Set(parseScopesToArray(requiredScopes));
  const requiredScopesArray = Array.from(requiredScopesSet);

  const hasAllRequiredScopes = requiredScopesArray.every((scope) =>
    scopesSet.has(scope)
  );

  if (options.strict) {
    return hasAllRequiredScopes && scopesSet.size === requiredScopesSet.size;
  }

  return hasAllRequiredScopes;
};

/**
 * Merges two space-separated scope strings into one, removing duplicates.
 * Properly handles whitespace by trimming and normalizing scope values.
 * @param scopes1 The first scope string
 * @param scopes2 The second scope string
 * @returns Merged scope string with unique scopes, sorted alphabetically for consistency
 */
export function mergeScopes(
  scopes1: string | undefined | null,
  scopes2: string | undefined | null
): string {
  const scopes1Array = scopes1 ? parseScopesToArray(scopes1) : [];
  const scopes2Array = scopes2 ? parseScopesToArray(scopes2) : [];

  // Use a Set to remove duplicates
  const uniqueScopes = new Set([...scopes1Array, ...scopes2Array]);

  // Convert back to array and join as a space-separated string
  return Array.from(uniqueScopes).join(" ");
}

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
 * 3. If multiple matches with the exact same scopes are found, we take the first one.
 *    However, this should not happen in practice as the session should not contain
 *    duplicate AccessTokenSet's.
 *
 * @param sessionData The session data containing accessTokens array.
 * @param {Object} options
 * @param {number} options.scope - The scope to match against (space-separated string).
 * @param {string} options.audience - The audience to match against.
 * @param {"requestedScope" | "scope"} [options.matchMode="requestedScope"] - The mode to use for matching scopes.
 * @returns The best matching AccessTokenSet, or undefined if no match is found.
 */
export function findAccessTokenSet(
  sessionData: SessionData | undefined,
  options: {
    scope?: string;
    audience: string;
    matchMode?: "requestedScope" | "scope";
    progressiveScopes: boolean;
  }
): AccessTokenSet | undefined {
  const matchMode = options.matchMode ?? "requestedScope";
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
      // When progressiveScopes is enabled, we consider it a match regardless of scope.
      (options.progressiveScopes ||
        compareScopes(
          matchMode === "scope"
            ? accessTokenSet.scope
            : (accessTokenSet.requestedScope ?? accessTokenSet.scope),
          options.scope,
          { strict: matchMode === "scope" }
        ))
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
  // Note: This sorting algorithm also takes care of duplicate scopes, as they will
  // be converted to a Set and thus have the same size as a non-duplicate scope array.
  allMatches.sort((a, b) => {
    const aScopesUnique = new Set(parseScopesToArray(a.scope));
    const bScopesUnique = new Set(parseScopesToArray(b.scope));

    return aScopesUnique.size - bScopesUnique.size;
  });

  // The first item in the sorted list is the best possible match.
  return allMatches[0];
}
