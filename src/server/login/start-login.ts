import { NextResponse } from "next/server.js";
import { calculateJwkThumbprint, exportJWK } from "jose";

import {
  DPoPError,
  DPoPErrorCode,
  InvalidConfigurationError,
  SdkError
} from "../../errors/index.js";
import type { StartInteractiveLoginOptions } from "../../types/index.js";
import {
  ANON_TRANSFER_TOKEN_PARAM,
  RESERVED_SESSION_TOKEN_PARAM,
  transferCookies
} from "../../utils/anonymous-session-constants.js";
import { resolveAppBaseUrl } from "../../utils/app-base-url.js";
import {
  mergeAuthorizationParamsIntoSearchParams,
  parseNonNegativeIntegerParam
} from "../../utils/authorization-params-helpers.js";
import { createRouteUrl } from "../../utils/pathUtils.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import { requestContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import type { PagesRouterRequest } from "../types/index.js";
import { resolveReturnTo } from "./return-to.js";

// Parameters of the authorize request that the caller cannot set (also dropped for CIBA, as on
// `main`).
export const INTERNAL_AUTHORIZE_PARAMS = [
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
 * Starts a login: the redirect to Auth0 with the transaction cookie.
 *
 * The engine builds the authorize URL, PKCE and `state` and writes the transaction; this adds what
 * is ours: the callback URL, a safe `returnTo`, the merged parameters and `dpop_jkt`.
 */
export async function startLogin(
  setup: EngineSetup,
  options: StartInteractiveLoginOptions = {},
  input?: Request | PagesRouterRequest
): Promise<NextResponse> {
  const { config } = setup;
  const { ctx, scratch, nextReq } = await requestContext(input);

  const appBaseUrl = resolveAppBaseUrl(config.appBaseUrl, nextReq);
  // Must be registered with the authorization server.
  const redirectUri = createRouteUrl(config.routes.callback, appBaseUrl);
  const returnTo = resolveReturnTo(
    options.returnTo,
    (config.authorizationParameters.redirect_uri as string | undefined) ||
      appBaseUrl,
    config.signInReturnToPath
  );

  const challengeMode = options.challengeMode || "redirect";
  if (challengeMode !== "redirect" && challengeMode !== "popup") {
    throw new InvalidConfigurationError(
      `Invalid challengeMode: ${challengeMode}. Expected 'redirect' or 'popup'.`
    );
  }
  if (challengeMode === "popup") {
    // Popup mode is 3.4.1b.
    return NextResponse.json({ error: "not_implemented" }, { status: 501 });
  }

  // The scope given per call replaces the configured one; a scope map is resolved for the audience.
  const authorizationParams = mergeAuthorizationParamsIntoSearchParams(
    config.authorizationParameters,
    options.authorizationParameters,
    INTERNAL_AUTHORIZE_PARAMS
  );

  if (typeof config.domain === "function") {
    assertOpenIdScope(setup, options);
  }

  const maxAge = authorizationParams.get("max_age");
  if (
    maxAge !== null &&
    parseNonNegativeIntegerParam("max_age", maxAge) === null
  ) {
    throw new InvalidConfigurationError(
      `Invalid max_age parameter: "${maxAge}". Must be a non-negative integer.`
    );
  }

  authorizationParams.set("redirect_uri", redirectUri.toString());
  const dpopKeyPair = await getDpopKeyPair(config);
  if (dpopKeyPair) {
    authorizationParams.set("dpop_jkt", await dpopThumbprint(dpopKeyPair));
  }

  const engine = await setup.getEngine();
  let authorizationUrl: URL;
  try {
    authorizationUrl = await setup.errors.callEngine("login", () =>
      engine.startInteractiveLogin(
        {
          authorizationParams: Object.fromEntries(authorizationParams),
          pushedAuthorizationRequests:
            config.options.pushedAuthorizationRequests,
          appState: { returnTo }
        },
        ctx
      )
    );
  } catch (e) {
    // A failing domain resolver or bad configuration is thrown, as on `main`.
    if (e instanceof SdkError) {
      throw e;
    }
    return new NextResponse(
      "An error occurred while trying to initiate the login request.",
      { status: 500 }
    );
  }

  const res = NextResponse.redirect(authorizationUrl.toString());
  transferCookies(scratch, res);
  return res;
}

/**
 * In resolver mode `openid` must be in the scope: from the configuration and the call together,
 * as on `main`. A scope map counts as its value for the audience.
 */
function assertOpenIdScope(
  setup: EngineSetup,
  options: StartInteractiveLoginOptions
) {
  const { config } = setup;
  const configured = config.authorizationParameters.scope;
  const given = options.authorizationParameters?.scope;
  const scope = [
    typeof configured === "string" ? configured : config.loginScope,
    typeof given === "string" ? given : undefined
  ]
    .filter(Boolean)
    .join(" ");
  if (!scope.split(/\s+/).includes("openid")) {
    throw new InvalidConfigurationError(
      'The "openid" scope is required in resolver mode (DomainResolver). ' +
        'Add "openid" to your SDK configuration or login options.'
    );
  }
}

async function dpopThumbprint(
  keyPair: NonNullable<Awaited<ReturnType<typeof getDpopKeyPair>>>
): Promise<string> {
  try {
    return await calculateJwkThumbprint(await exportJWK(keyPair.publicKey));
  } catch (error) {
    throw new DPoPError(
      DPoPErrorCode.DPOP_JKT_CALCULATION_FAILED,
      "DPoP is enabled but failed to calculate key thumbprint (dpop_jkt). " +
        "This is required for secure DPoP binding. Please check your key configuration.",
      error instanceof Error ? error : undefined
    );
  }
}
