import type { AuthorizationParameters } from "../types/index.js";
import { getScopeForAudience } from "./scope-helpers.js";

/**
 * Merges two instances of authorization parameters into a URLSearchParams object,
 * excluding any parameters specified in the excludedParams array.
 * If the scope is provided as a map of audience to scopes, it selects the appropriate scope
 * based on the audience parameter.
 * @param leftParams The base authorization parameters
 * @param rightParams The authorization parameters to merge, overriding leftParams
 * @param excludedParams Array of parameter names to exclude from the resulting URLSearchParams
 * @returns URLSearchParams containing the merged authorization parameters
 *
 * @remarks The scope properties override each other, no merging is done.
 * @throws {InvalidConfigurationError} If scope is defined as a map but no audience is provided.
 */
export function mergeAuthorizationParamsIntoSearchParams(
  leftParams: AuthorizationParameters,
  rightParams?: AuthorizationParameters,
  excludedParams: string[] = []
): URLSearchParams {
  const authorizationParams = new URLSearchParams();

  // First we merge the two sets of authorization parameters,
  // with the rightParams taking precedence over leftParams.
  // We then iterate over the merged object and add each key/value pair to the URLSearchParams,
  // excluding any keys specified in excludedParams.
  // We also skip any keys with null or undefined values.
  // Additionally, when the scope is provided as a map of audience to scopes, we need to pick the correct
  // scope for the current audience.
  const mergedAuthorizationParams: AuthorizationParameters = {
    ...leftParams,
    ...rightParams
  };

  Object.entries(mergedAuthorizationParams).forEach(([key, val]) => {
    if (!excludedParams || (!excludedParams.includes(key) && val != null)) {
      // When the scope is provided as a map of audience to scopes, we need to pick the correct
      // scope for the current audience.
      if (key === "scope" && typeof val === "object") {
        val = getScopeForAudience(
          val as { [audience: string]: string },
          mergedAuthorizationParams.audience
        );
      }

      // Only when the value is not null or undefined, we set it.
      // This allows to use values such as empty string or 0,
      // which are falsy but valid values for authorization parameters.
      if (val != null) {
        authorizationParams.set(key, String(val));
      }
    }
  });

  return authorizationParams;
}
