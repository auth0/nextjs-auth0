import type { NextRequest, NextResponse } from "next/server.js";

import type {
  SessionTransferTokenOptions,
  SessionTransferTokenResult
} from "../../types/index.js";
import { DEFAULT_SCOPES, DEFAULT_STT_SCOPES } from "../../utils/constants.js";
import { resolveActorFromSession } from "../../utils/session-transfer-helpers.js";
import { mergeScopes } from "../../utils/token-set-helpers.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import { withCallContext } from "../engine/call-context.js";
import type { CookieContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { readSession } from "../session/read-session.js";
import type {
  PagesRouterRequest,
  PagesRouterResponse
} from "../types/index.js";
import { checkSubject, toExtra } from "./exchange-options.js";
import { createRefreshHook } from "./refresh-hook.js";

/**
 * `requestSessionTransferToken(options)` and `(req, res, options)`.
 */
export async function requestSessionTransferToken(
  setup: EngineSetup,
  req: PagesRouterRequest | NextRequest | undefined,
  res: PagesRouterResponse | NextResponse | undefined,
  options: SessionTransferTokenOptions
): Promise<SessionTransferTokenResult> {
  return withCallContext(req, res, (ctx) => transfer(setup, ctx, options));
}

/**
 * A session transfer token for the signed-in agent. The engine resolves the actor (the explicit
 * one, else the session ID token, refreshed first when it has expired: our `beforeSessionSaved`
 * runs and the session is saved), sends the exchange and checks the issued token type. Around it,
 * `main`'s rules:
 * 1. the session is read with `main`'s checks; stored for another domain: the
 *    `SessionDomainMismatchError`, even with an explicit actor
 * 2. `main`'s subject checks
 * 3. no session (or a ceiling reached) and no explicit actor: `main`'s `actor_unavailable`, before
 *    the engine, whose own read has no ceiling check
 * 4. the scope is `main`'s defaults merged with the caller's; `organization` and `reason` only
 *    when given
 * 5. MFA asked on the actor refresh: `MfaRequiredError`
 */
async function transfer(
  setup: EngineSetup,
  ctx: CookieContext,
  options: SessionTransferTokenOptions
): Promise<SessionTransferTokenResult> {
  const { state, error } = await readSession(setup, ctx);
  if (error) {
    throw error;
  }
  const subjectError = checkSubject(options);
  if (subjectError) {
    throw subjectError;
  }
  if (!options.actor && !state) {
    const [actorError] = resolveActorFromSession(null);
    throw actorError;
  }

  const dpopKeyPair = await getDpopKeyPair(setup.config);
  const hook = createRefreshHook(setup);
  let result;
  try {
    const engine = await setup.getEngine();
    result = await engine.requestSessionTransferToken(
      {
        subjectToken: options.subjectToken,
        subjectTokenType: options.subjectTokenType,
        actor: options.actor,
        scope: mergeScopes(DEFAULT_STT_SCOPES, options.scope),
        organization: options.organization || undefined,
        reason: options.reason || undefined,
        extra: toExtra(options.additionalParameters),
        beforeSessionSaved: hook.beforeSessionSaved
      },
      ctx,
      dpopKeyPair ? { dpopKeyPair } : undefined
    );
  } catch (e) {
    // `beforeSessionSaved` errors reach the app as thrown, as on `main`; nothing was saved.
    if (hook.failed) {
      throw e;
    }
    // `main` encrypts the MFA token of the actor refresh with no audience and the login scope.
    throw await setup.errors.toSdkError(e, "sessionTransfer", {
      audience: "",
      scope: DEFAULT_SCOPES
    });
  }

  return {
    sessionTransferToken: result.sessionTransferToken,
    issuedTokenType: result.issuedTokenType,
    expiresIn: result.expiresIn,
    tokenType: result.tokenType
  };
}
