import { NextResponse } from "next/server.js";
import { calculateJwkThumbprint, exportJWK } from "jose";

import {
  DPoPError,
  DPoPErrorCode,
  InvalidConfigurationError,
  SdkError
} from "../../errors/index.js";
import type { StartInteractiveLoginOptions } from "../../types/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import { resolveAppBaseUrl } from "../../utils/app-base-url.js";
import { parseNonNegativeIntegerParam } from "../../utils/authorization-params-helpers.js";
import { createRouteUrl } from "../../utils/pathUtils.js";
import { getScopeForAudience } from "../../utils/scope-helpers.js";
import { toSafeRedirect } from "../../utils/url-helpers.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import { requestContext } from "../engine/adapters/context.js";
import {
  withoutUnsupportedParams,
  type EngineSetup
} from "../engine/create-engine.js";
import type { PagesRouterRequest } from "../types/index.js";

// `returnTo` is stored in the transaction cookie, so it is capped as on nextjs.
const MAX_RETURN_TO_BYTES = 2048;
let clampWarned = false;

/**
 * Starts a login: the redirect to Auth0 with the transaction cookie.
 *
 * The engine builds the authorize URL, PKCE and `state` and writes the transaction; this adds what
 * is ours: the callback URL, a safe `returnTo`, a scope map resolved for the audience and
 * `dpop_jkt`.
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
    // Popup mode is not built yet.
    return NextResponse.json({ error: "not_implemented" }, { status: 501 });
  }

  // The call's parameters go to the engine as they are: it puts them over its defaults and leaves
  // out a `null` or `undefined`, so a call can remove a configured value. What it cannot do is
  // ours: ignore the parameters it does not honor, resolve a scope map for the audience of this
  // login, and check `max_age`.
  const { audience, scope, max_age } = {
    ...config.authorizationParameters,
    ...options.authorizationParameters
  };
  const authorizationParams: Record<string, unknown> = {
    ...withoutUnsupportedParams(options.authorizationParameters ?? {}),
    redirect_uri: redirectUri.toString()
  };
  if (typeof scope === "object" && scope !== null) {
    authorizationParams.scope = getScopeForAudience(scope, audience);
  }

  if (
    max_age != null &&
    parseNonNegativeIntegerParam("max_age", String(max_age)) === null
  ) {
    throw new InvalidConfigurationError(
      `Invalid max_age parameter: "${max_age}". Must be a non-negative integer.`
    );
  }

  const dpopKeyPair = await getDpopKeyPair(config);
  if (dpopKeyPair) {
    authorizationParams.dpop_jkt = await dpopThumbprint(dpopKeyPair);
  }

  const engine = await setup.getEngine();
  let authorizationUrl: URL;
  try {
    authorizationUrl = await setup.errors.callEngine("login", () =>
      engine.startInteractiveLogin(
        {
          authorizationParams,
          pushedAuthorizationRequests:
            config.options.pushedAuthorizationRequests,
          appState: { returnTo }
        },
        ctx
      )
    );
  } catch (e) {
    // A failing domain resolver or bad configuration is thrown, as on nextjs.
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
 * The path to go to after login (or a connect account flow): `returnTo` when it stays on the
 * app's origin, else the default. An unsafe or oversized value silently becomes the default, as on
 * nextjs.
 */
export function resolveReturnTo(
  returnTo: string | undefined,
  safeBaseUrl: string,
  fallback: string
): string {
  if (!returnTo) {
    return fallback;
  }
  const safe = toSafeRedirect(returnTo, new URL(safeBaseUrl));
  if (!safe) {
    return fallback;
  }
  const path = safe.pathname + safe.search + safe.hash;
  if (new TextEncoder().encode(path).length <= MAX_RETURN_TO_BYTES) {
    return path;
  }
  if (!clampWarned) {
    clampWarned = true;
    console.warn(
      `[auth0] returnTo value exceeds ${MAX_RETURN_TO_BYTES} bytes; clamping to ${fallback} to keep the transaction cookie under the header size limit. Shorten the returnTo value in your application.`
    );
  }
  return fallback;
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
