import { AuthorizationParameters } from "../types/index.js";
import { DEFAULT_SCOPES } from "./constants.js";

/**
 * Determines the default scope based on the provided authorization parameters.
 * If no scope is defined, it defaults to a predefined set of scopes.
 * If the scope is defined as an object (map) and does not include a scope for the default audience,
 * it adds the default scopes for that audience.
 * @param authorizationParameters The authorization parameters to evaluate.
 * @returns The determined scope, either as a string or an updated map of scopes.
 */
export function ensureDefaultScope(
  authorizationParameters: AuthorizationParameters
) {
  // When no scope is defined in the constructor, we default to a string set to DEFAULT_SCOPES.
  // We do not introduce a Map here as that would be a breaking change.
  if (!authorizationParameters.scope) {
    return DEFAULT_SCOPES;
  }

  // When the user defined scope as a Map, but did not define a scope for the default audience,
  // we need to default it to the DEFAULT_SCOPES
  if (
    typeof authorizationParameters.scope === "object" &&
    !getScopeForAudience(
      authorizationParameters.scope,
      authorizationParameters.audience
    )
  ) {
    const audience = authorizationParameters.audience!;

    return {
      ...authorizationParameters.scope,
      [audience]: DEFAULT_SCOPES
    };
  }

  return authorizationParameters.scope;
}

/**
 * Retrieves the appropriate scope for a given audience from a scope map.
 * Only consideres the audience when the scope is of type Map<string, string>.
 * If the scope is a string, it is returned as-is.
 * If the scope is null or undefined, undefined is returned.
 * @param scope The scope, either as a string, null/undefined, or a Map of audience to scope.
 * @param audience The audience to look up in the scope map
 * @returns
 */
export function getScopeForAudience(
  scope: string | null | undefined | { [key: string]: string },
  audience: string | null | undefined
): string | undefined {
  // When the scope is null or undefined, we return undefined
  if (!scope) {
    return undefined;
  }

  // When the scope is a string, we return it as-is
  if (typeof scope === "string") {
    return scope;
  }

  // When no audience is provided, we cannot look up the scope in the Map
  // We throw an error to inform the user that an audience is required
  // Which is required to use MRRT altogether.
  if (!audience) {
    throw new Error(
      "When defining scope as a Map, an audience is required to look up the correct scope."
    );
  }

  // When the scope is a Map, we return the scope for the provided audience
  // When no audience is provided, we default to the 'default' audience.
  return scope[audience];
}
