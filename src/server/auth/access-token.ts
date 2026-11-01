import type { NextRequest, NextResponse } from "next/server.js";
import type {
  TokenSet as EngineTokenSet,
  StateData
} from "@auth0/auth0-server-js";

import {
  AccessTokenError,
  AccessTokenErrorCode,
  MfaRequiredError,
  SdkError,
  TokenRevocationError,
  TokenRevocationErrorCode
} from "../../errors/index.js";
import type { GetAccessTokenOptions } from "../../types/index.js";
import { getScopeForAudience } from "../../utils/scope-helpers.js";
import { compareScopes, mergeScopes } from "../../utils/token-set-helpers.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import { withCallContext } from "../engine/adapters/call-context.js";
import { readContext, type CookieContext } from "../engine/adapters/context.js";
import { ENGINE_DEFAULT_AUDIENCE } from "../engine/adapters/session-mapper.js";
import type { EngineSetup } from "../engine/create-engine.js";
import type { EngineConfig } from "../engine/resolve-config.js";
import type {
  PagesRouterRequest,
  PagesRouterResponse
} from "../types/index.js";
import { createRefreshHook } from "./hooks.js";
import { readSession } from "./session.js";

export interface AccessToken {
  token: string;
  expiresAt: number;
  scope?: string;
  token_type?: string;
  audience?: string;
}

/**
 * The outcome of {@link retrieveAccessToken}. A token error is returned, not thrown, as nextjs's
 * `getTokenSet` does, so the route can answer it while anything else (a hook error) propagates.
 */
export type AccessTokenResult =
  | { accessToken: AccessToken; refreshed: boolean; error?: undefined }
  | { error: SdkError };

/**
 * `getAccessToken()` and `getAccessToken(req, res)`: the middleware and Pages Router forms write
 * to the response given, the App Router form to `cookies()`, where a Server Component refuses the
 * write and the token is still returned. The arguments are already checked.
 */
export async function getAccessToken(
  setup: EngineSetup,
  req: PagesRouterRequest | NextRequest | undefined,
  res: PagesRouterResponse | NextResponse | undefined,
  options: GetAccessTokenOptions
): Promise<AccessToken> {
  return withCallContext(req, res, async (ctx) =>
    unwrap(await retrieveAccessToken(setup, ctx, options))
  );
}

/**
 * The access token for the signed-in user. The engine looks it up, refreshes it when needed and
 * saves the session; around it, nextjs's rules (`executeGetAccessToken`, `getTokenSet`):
 * 1. no session (or a ceiling reached): `missing_session`; resolver mode, stored for another
 *    domain: the `SessionDomainMismatchError`
 * 2. the scope is computed as on nextjs and always passed, so the engine sends it to Auth0
 * 3. no refresh token and a token that has not expired: served, even with `refresh` or inside
 *    `tokenRefreshBuffer` (the engine would refuse)
 * 4. on a refresh, just before the save, the new ID token claims go to `user`, then
 *    `beforeSessionSaved` (or the default claim filter) runs
 * 5. MFA required: the unchanged session is saved again, then the error is returned
 *
 * `refreshed` is `true` when a new token was fetched and the session saved.
 */
export async function retrieveAccessToken(
  setup: EngineSetup,
  ctx: CookieContext,
  options: GetAccessTokenOptions
): Promise<AccessTokenResult> {
  const { config, sessionMapper } = setup;
  const { state, error } = await readSession(setup, ctx);
  if (error) {
    return { error };
  }
  if (!state) {
    return {
      error: new AccessTokenError(
        AccessTokenErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      )
    };
  }

  const audience = options.audience ?? undefined;
  const scope = tokenScope(config, {
    audience,
    scope: options.scope ?? undefined,
    mergeScopes: options.mergeScopes
  });
  const cached = findTokenSet(
    state,
    audience ?? sessionMapper.defaultAudienceKey,
    scope
  );

  if (!state.refreshToken && cached && cached.expiresAt > Date.now() / 1000) {
    return {
      accessToken: toAccessToken(cached, audience),
      refreshed: false
    };
  }

  const engine = await setup.getEngine();
  const dpopKeyPair = await getDpopKeyPair(config);
  const hook = createRefreshHook(setup);
  let tokenSet: EngineTokenSet;
  try {
    tokenSet = await engine.getAccessToken(
      { audience, scope, refresh: !!options.refresh },
      ctx,
      dpopKeyPair ? { dpopKeyPair } : undefined,
      { beforeSessionSaved: hook.beforeSessionSaved }
    );
  } catch (e) {
    // `beforeSessionSaved` errors reach the app as thrown, as on nextjs; nothing was saved.
    if (hook.failed) {
      throw e;
    }
    const mapped = await setup.errors.toSdkError(e, "refresh", {
      audience,
      scope,
      accessTokenFound: !!cached
    });
    if (!(mapped instanceof SdkError)) {
      throw mapped;
    }
    if (mapped instanceof MfaRequiredError) {
      await setup.sessionStore.set(
        config.sessionCookie.name,
        state,
        false,
        ctx
      );
    }
    return { error: mapped };
  }

  return {
    accessToken: toAccessToken(tokenSet, audience),
    refreshed: hook.ran
  };
}

function unwrap(result: AccessTokenResult): AccessToken {
  if (result.error) {
    throw result.error;
  }
  return result.accessToken;
}

/**
 * The token the engine serves for this audience and scope, if any (its `getAccessToken` lookup).
 */
function findTokenSet(
  state: StateData,
  audience: string,
  scope: string
): EngineTokenSet | undefined {
  return state.tokenSets.find(
    (tokenSet) =>
      tokenSet.audience === audience &&
      (!scope || compareScopes(tokenSet.scope, scope))
  );
}

function toAccessToken(
  tokenSet: EngineTokenSet,
  audience: string | undefined
): AccessToken {
  return {
    token: tokenSet.accessToken,
    scope: tokenSet.scope,
    expiresAt: tokenSet.expiresAt,
    token_type: tokenSet.tokenType,
    // Only the engine's own placeholder is hidden; a configured or per-login audience is returned
    // as stored, as nextjs does.
    audience:
      tokenSet.audience === ENGINE_DEFAULT_AUDIENCE
        ? audience
        : tokenSet.audience
  };
}

/**
 * The scope an access token is looked up and refreshed with, as nextjs computes it
 * (`getTokenSet`): the configured scope for the audience merged with `scope`, or `scope` alone
 * with `mergeScopes: false`. A scope map without an audience throws, as on nextjs.
 */
function tokenScope(
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

/**
 * Revokes the session's refresh token at Auth0, with nextjs's errors: no session, in resolver mode a
 * session stored for another domain (`SessionDomainMismatchError`), no refresh token. The session is not changed
 * and no cookie is written.
 */
export async function revokeRefreshToken(
  setup: EngineSetup,
  input?: Request | PagesRouterRequest
): Promise<void> {
  const { ctx } = await readContext(input);
  const { state, error } = await readSession(setup, ctx);
  if (error) {
    throw error;
  }
  if (!state) {
    throw new TokenRevocationError(
      TokenRevocationErrorCode.MISSING_SESSION,
      "The user does not have an active session."
    );
  }
  if (!state.refreshToken?.trim()) {
    throw new TokenRevocationError(
      TokenRevocationErrorCode.MISSING_REFRESH_TOKEN,
      "The session does not contain a refresh token to revoke."
    );
  }

  const { refreshToken } = state;
  // Passed explicitly, so in static mode the engine does not read the session again.
  await setup.errors.callEngine("revoke", async () =>
    (await setup.getEngine()).revokeRefreshToken({ token: refreshToken }, ctx)
  );
}
