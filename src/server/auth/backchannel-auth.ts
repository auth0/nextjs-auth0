import {
  BackchannelAuthenticationNotSupportedError,
  InvalidConfigurationError
} from "../../errors/index.js";
import type {
  BackchannelAuthenticationOptions,
  BackchannelAuthenticationResponse
} from "../../types/index.js";
import {
  ANON_TRANSFER_TOKEN_PARAM,
  RESERVED_SESSION_TOKEN_PARAM
} from "../../utils/anonymous-session-constants.js";
import { mergeAuthorizationParamsIntoSearchParams } from "../../utils/authorization-params-helpers.js";
import { DEFAULT_SCOPES } from "../../utils/constants.js";
import type { EngineSetup } from "../engine/create-engine.js";

// Parameters of the authorize request that the caller cannot set, as on nextjs.
const INTERNAL_AUTHORIZE_PARAMS = [
  "client_id",
  "redirect_uri",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "state",
  "nonce",
  RESERVED_SESSION_TOKEN_PARAM,
  ANON_TRANSFER_TOKEN_PARAM
];

/**
 * CIBA: the engine's auth client sends the request to Auth0 and polls until the user approves,
 * then the tokens are returned. Nothing is saved, as on nextjs. nextjs's checks and parameter
 * rules come first: the tenant supports CIBA, and internal or `null` parameters are not sent.
 */
export async function backchannelAuthentication(
  setup: EngineSetup,
  options: BackchannelAuthenticationOptions
): Promise<BackchannelAuthenticationResponse> {
  const { config } = setup;
  // The engine's auth client only exists with a static domain.
  if (typeof config.domain === "function") {
    throw new InvalidConfigurationError(
      "getTokenByBackchannelAuth is not yet supported in resolver mode (DomainResolver)."
    );
  }

  const engine = await setup.getEngine();
  return setup.errors.callEngine("backchannelAuthentication", async () => {
    const authClient = engine.authClient;
    const metadata = await authClient.getServerMetadata();
    if (!metadata.backchannel_authentication_endpoint) {
      throw new BackchannelAuthenticationNotSupportedError();
    }

    // The scope given per call replaces the configured one; a scope map is resolved for the audience.
    const params = mergeAuthorizationParamsIntoSearchParams(
      config.authorizationParameters,
      options.authorizationParams,
      INTERNAL_AUTHORIZE_PARAMS
    );
    if (!params.get("scope")) {
      params.set("scope", DEFAULT_SCOPES);
    }
    // The engine adds the configured parameters underneath; a key set to `undefined` is not sent,
    // so the request has only what nextjs sent.
    const authorizationParams = {
      ...Object.fromEntries(
        Object.keys(config.authorizationParameters).map((key) => [
          key,
          undefined
        ])
      ),
      ...Object.fromEntries(params)
    };

    // No DPoP, as on nextjs.
    const response = await authClient.backchannelAuthentication({
      bindingMessage: options.bindingMessage,
      loginHint: options.loginHint,
      requestedExpiry: options.requestedExpiry,
      authorizationDetails: options.authorizationDetails,
      authorizationParams
    });

    return {
      tokenSet: {
        accessToken: response.accessToken,
        idToken: response.idToken,
        scope: response.scope,
        refreshToken: response.refreshToken,
        expiresAt: response.expiresAt
      },
      idTokenClaims: response.claims,
      authorizationDetails: response.authorizationDetails
    };
  });
}
