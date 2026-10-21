import { getScopeForAudience } from "../../utils/scope-helpers.js";
import { mergeScopes } from "../../utils/token-set-helpers.js";
import type { EngineConfig } from "../engine/resolve-config.js";

/**
 * The scope an access token is looked up and refreshed with, as `main` computes it
 * (`getTokenSet`): the configured scope for the audience merged with `scope`, or `scope` alone
 * with `mergeScopes: false`. A scope map without an audience throws, as on `main`.
 */
export function tokenScope(
  config: EngineConfig,
  {
    audience,
    scope,
    mergeScopes: merge
  }: { audience?: string; scope?: string; mergeScopes?: boolean }
): string {
  if (merge === false) {
    return scope || "";
  }
  const { authorizationParameters } = config;
  return mergeScopes(
    getScopeForAudience(
      authorizationParameters.scope,
      audience ?? authorizationParameters.audience
    ),
    scope
  );
}
