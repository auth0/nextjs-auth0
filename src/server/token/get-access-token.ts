import type { NextRequest, NextResponse } from "next/server.js";
import type {
  TokenSet as EngineTokenSet,
  StateData
} from "@auth0/auth0-server-js";

import {
  AccessTokenError,
  AccessTokenErrorCode,
  MfaRequiredError,
  SdkError
} from "../../errors/index.js";
import type { GetAccessTokenOptions } from "../../types/index.js";
import { compareScopes } from "../../utils/token-set-helpers.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import { withCallContext } from "../engine/call-context.js";
import type { CookieContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { readSession } from "../session/read-session.js";
import type {
  PagesRouterRequest,
  PagesRouterResponse
} from "../types/index.js";
import { createRefreshHook } from "./refresh-hook.js";
import { tokenScope } from "./token-scope.js";

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
 * 1. no session (or a ceiling reached): `missing_session`; stored for another domain: the
 *    `SessionDomainMismatchError`
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
      accessToken: toAccessToken(setup, cached, audience),
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
    accessToken: toAccessToken(setup, tokenSet, audience),
    refreshed: hook.ran
  };
}

type CachedTokenSet = EngineTokenSet & { requestedScope?: string };

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
  // `requestedScope` is internal to the engine, so not in its published type.
  return (state.tokenSets as CachedTokenSet[]).find(
    (tokenSet) =>
      tokenSet.audience === audience &&
      (!scope ||
        (tokenSet.requestedScope ?? tokenSet.scope) === scope ||
        compareScopes(tokenSet.scope, scope))
  );
}

function toAccessToken(
  { sessionMapper }: EngineSetup,
  tokenSet: EngineTokenSet,
  audience: string | undefined
): AccessToken {
  return {
    token: tokenSet.accessToken,
    scope: tokenSet.scope,
    expiresAt: tokenSet.expiresAt,
    token_type: tokenSet.tokenType,
    // The login token is filed under the engine's key; nextjs returns the audience asked for.
    audience:
      tokenSet.audience === sessionMapper.defaultAudienceKey
        ? audience
        : tokenSet.audience
  };
}
