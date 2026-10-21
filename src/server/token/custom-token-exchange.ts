import type {
  ActClaim,
  CustomTokenExchangeOptions,
  CustomTokenExchangeResponse
} from "../../types/index.js";
import { DEFAULT_SCOPES } from "../../utils/constants.js";
import { mergeScopes } from "../../utils/token-set-helpers.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import { readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { checkActor, checkSubject, toExtra } from "./exchange-options.js";

/**
 * Custom Token Exchange (RFC 8693), nothing saved. The engine sends the request (DPoP when on);
 * around it, `main`'s rules:
 * 1. `main`'s checks first, for `main`'s codes and texts
 * 2. the scope is `main`'s defaults merged with the caller's; `audience` and `organization` only
 *    when given
 * 3. `act` from the ID token whenever there is one, `tokenType` defaults to `Bearer`
 */
export async function customTokenExchange(
  setup: EngineSetup,
  options: CustomTokenExchangeOptions
): Promise<CustomTokenExchangeResponse> {
  const error = checkSubject(options) ?? checkActor(options);
  if (error) {
    throw error;
  }

  // Domain from the request headers (resolver mode), as `main`'s `forRequest(headers())`.
  const { ctx } = await readContext();
  const dpopKeyPair = await getDpopKeyPair(setup.config);
  const response = await setup.errors.callEngine(
    "customTokenExchange",
    async () =>
      (await setup.getEngine()).customTokenExchange(
        {
          subjectToken: options.subjectToken,
          subjectTokenType: options.subjectTokenType,
          scope: mergeScopes(DEFAULT_SCOPES, options.scope),
          audience: options.audience || undefined,
          organization: options.organization || undefined,
          actorToken: options.actorToken,
          actorTokenType: options.actorTokenType,
          extra: toExtra(options.additionalParameters)
        },
        ctx,
        dpopKeyPair ? { dpopKeyPair } : undefined
      )
  );

  return {
    accessToken: response.accessToken,
    idToken: response.idToken,
    refreshToken: response.refreshToken,
    tokenType: response.tokenType ?? "Bearer",
    // `main` gave `Number(expires_in)`, so `NaN` when Auth0 sent none.
    expiresIn: response.expiresIn ?? NaN,
    scope: response.scope,
    // `main`'s rule (the ID token's `act`), and the engine's from the access token when the
    // request had an actor token and the ID token has none.
    act: (response.claims?.act as ActClaim | undefined) ?? response.act
  };
}
