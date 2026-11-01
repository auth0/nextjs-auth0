import type { NextRequest, NextResponse } from "next/server.js";

import {
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode
} from "../../errors/index.js";
import type {
  ActClaim,
  CustomTokenExchangeOptions,
  CustomTokenExchangeResponse,
  SessionTransferTokenOptions,
  SessionTransferTokenResult
} from "../../types/index.js";
import { DEFAULT_SCOPES, DEFAULT_STT_SCOPES } from "../../utils/constants.js";
import { resolveActorFromSession } from "../../utils/session-transfer-helpers.js";
import { mergeScopes } from "../../utils/token-set-helpers.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import { withCallContext } from "../engine/adapters/call-context.js";
import { readContext, type CookieContext } from "../engine/adapters/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import type {
  PagesRouterRequest,
  PagesRouterResponse
} from "../types/index.js";
import { createRefreshHook } from "./hooks.js";
import { readSession } from "./session.js";

/**
 * Custom Token Exchange (RFC 8693), nothing saved. The engine sends the request (DPoP when on);
 * around it, nextjs's rules:
 * 1. nextjs's checks first, for nextjs's codes and texts
 * 2. the scope is nextjs's defaults merged with the caller's; `audience` and `organization` only
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

  // Domain from the request headers (resolver mode), as nextjs's `forRequest(headers())`.
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
    // nextjs gave `Number(expires_in)`, so `NaN` when Auth0 sent none.
    expiresIn: response.expiresIn ?? NaN,
    scope: response.scope,
    // nextjs's rule (the ID token's `act`), and the engine's from the access token when the
    // request had an actor token and the ID token has none.
    act: (response.claims?.act as ActClaim | undefined) ?? response.act
  };
}

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
 * nextjs's rules:
 * 1. the session is read with nextjs's checks; resolver mode, stored for another domain: the
 *    `SessionDomainMismatchError`, even with an explicit actor
 * 2. nextjs's subject checks
 * 3. no session (or a ceiling reached) and no explicit actor: nextjs's `actor_unavailable`, before
 *    the engine, whose own read has no ceiling check
 * 4. the scope is nextjs's defaults merged with the caller's; `organization` and `reason` only
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
    // `beforeSessionSaved` errors reach the app as thrown, as on nextjs; nothing was saved.
    if (hook.failed) {
      throw e;
    }
    // nextjs encrypts the MFA token of the actor refresh with no audience and the login scope.
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

/**
 * nextjs's subject token checks (custom token exchange and session transfer), with nextjs's codes
 * and texts. They run before the engine, whose own checks give `EXCHANGE_FAILED`.
 */
function checkSubject(options: {
  subjectToken: string;
  subjectTokenType: string;
}): CustomTokenExchangeError | null {
  if (!options.subjectToken || options.subjectToken.trim() === "") {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.MISSING_SUBJECT_TOKEN,
      "The subject_token is required and cannot be empty."
    );
  }
  // 10 to 100 characters: the Auth0 Token Exchange Profile rule for `subject_token_type`.
  const type = options.subjectTokenType;
  if (type.length < 10) {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE,
      `Invalid subject_token_type: must be at least 10 characters. Received ${type.length} characters.`
    );
  }
  if (type.length > 100) {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE,
      `Invalid subject_token_type: must be at most 100 characters. Received ${type.length} characters.`
    );
  }
  return checkTokenTypeUri(type, "subject_token_type");
}

/**
 * nextjs's actor token checks for custom token exchange: a type with an actor token, as a URI.
 */
function checkActor(options: {
  actorToken?: string;
  actorTokenType?: string;
}): CustomTokenExchangeError | null {
  if (options.actorToken && !options.actorTokenType) {
    return new CustomTokenExchangeError(
      CustomTokenExchangeErrorCode.MISSING_ACTOR_TOKEN_TYPE,
      "The actor_token_type is required when actor_token is provided."
    );
  }
  if (options.actorToken && options.actorTokenType) {
    return checkTokenTypeUri(options.actorTokenType, "actor_token_type");
  }
  return null;
}

function checkTokenTypeUri(
  type: string,
  field: "subject_token_type" | "actor_token_type"
): CustomTokenExchangeError | null {
  let isValidUrl = false;
  try {
    new URL(type);
    isValidUrl = true;
  } catch {
    // Not a URL; a URN is checked next.
  }

  // URN format: urn:<nid>:<nss> where nid is alphanumeric (can contain hyphens)
  const isValidUrn =
    /^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$/i.test(type);

  if (!isValidUrl && !isValidUrn) {
    return new CustomTokenExchangeError(
      field === "actor_token_type"
        ? CustomTokenExchangeErrorCode.INVALID_ACTOR_TOKEN_TYPE
        : CustomTokenExchangeErrorCode.INVALID_SUBJECT_TOKEN_TYPE,
      `Invalid ${field}: must be a valid URI (URL or URN format). Received: "${type}"`
    );
  }
  return null;
}

/**
 * `additionalParameters` as the engine's `extra`: null and undefined dropped, every other value
 * sent as `String(value)`, as on nextjs. The engine skips the parameters it sets itself.
 */
function toExtra(
  additionalParameters: Record<string, unknown> | undefined
): Record<string, string> | undefined {
  if (!additionalParameters) {
    return undefined;
  }
  const extra: Record<string, string> = {};
  for (const [key, value] of Object.entries(additionalParameters)) {
    if (value !== undefined && value !== null) {
      extra[key] = String(value);
    }
  }
  return extra;
}
