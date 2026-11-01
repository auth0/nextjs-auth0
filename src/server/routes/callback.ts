import { NextRequest, NextResponse } from "next/server.js";
import type { StateData, TransactionData } from "@auth0/auth0-server-js";

import {
  AuthorizationCodeGrantError,
  AuthorizationError,
  InvalidConfigurationError,
  InvalidStateError,
  MissingStateError,
  OAuth2Error,
  SdkError
} from "../../errors/index.js";
import { RESPONSE_TYPES, type SessionData } from "../../types/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import { resolveAppBaseUrl } from "../../utils/app-base-url.js";
import { normalizeDomain } from "../../utils/normalize.js";
import { createRouteUrl } from "../../utils/pathUtils.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import { middlewareContext } from "../engine/context.js";
import type { Engine, EngineSetup } from "../engine/create-engine.js";
import { addCacheControlHeadersForSession } from "../http/cache-control.js";
import { finalizeSession } from "../session/hooks.js";
import type { OnCallbackContext, OnCallbackHook } from "../types/hooks.js";

type InteractiveLoginResult = Awaited<
  ReturnType<Engine["completeInteractiveLogin"]>
>;

/**
 * What the login stores in the transaction as `appState`.
 */
interface LoginAppState {
  returnTo?: string;
  challengeMode?: "redirect" | "popup";
}

/**
 * Route: GET /auth/callback. The engine exchanges the code and builds the session; just before it
 * saves, it calls the hook below, which runs `onCallback` and `beforeSessionSaved` in nextjs's
 * order. Anything thrown there stops the save.
 *
 * A passwordless magic link returns here too: its transaction has no PKCE verifier (the
 * engine's marker for it), and the engine completes it with `completePasswordlessMagicLink`.
 */
export async function handleCallback(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  const { config } = setup;
  const state = req.nextUrl.searchParams.get("state");

  // Without parallel transactions the engine sends no `state`, so none comes back.
  if (!state && config.enableParallelTransactions) {
    return handleCallbackError(new MissingStateError(), {}, req, setup);
  }

  const scratch = NextResponse.next();
  const ctx = middlewareContext(req, scratch);

  // Read the transaction here too, so errors can carry `returnTo` as on nextjs.
  const found = await findTransaction(setup, state, ctx);
  if (!found) {
    return onCallbackOf(setup)(new InvalidStateError(), {}, null);
  }

  const { transaction, identifier, magicLink } = found;
  const appState = transaction.appState as LoginAppState | undefined;
  const appBaseUrl = resolveAppBaseUrl(config.appBaseUrl, req);
  // Reported by the engine once the code is exchanged; `false` until then.
  let anonymousSessionLinked: boolean | undefined;
  const callbackCtx = (): OnCallbackContext => ({
    responseType: RESPONSE_TYPES.CODE,
    // The engine's magic-link transaction has no `returnTo`; nextjs stored this one.
    returnTo: magicLink ? config.signInReturnToPath : appState?.returnTo,
    challengeMode: appState?.challengeMode || "redirect",
    appBaseUrl,
    anonymousSessionLinked: anonymousSessionLinked ?? false
  });

  // As on nextjs: the `state` stored in the transaction must be the one that came back.
  if (
    config.enableParallelTransactions &&
    typeof transaction.state === "string" &&
    transaction.state !== state
  ) {
    return handleCallbackError(
      new AuthorizationError({
        cause: new OAuth2Error({ code: "unknown_error" })
      }),
      callbackCtx(),
      req,
      setup,
      identifier
    );
  }

  if (!magicLink && (await hasWrongIssuer(setup, req, transaction))) {
    return handleCallbackError(
      new AuthorizationError({
        cause: new OAuth2Error({ code: "unknown_error" })
      }),
      callbackCtx(),
      req,
      setup,
      identifier
    );
  }

  if (appState?.challengeMode === "popup") {
    // Popup mode is not built yet.
    return NextResponse.json({ error: "not_implemented" }, { status: 501 });
  }

  // The engine derives `redirect_uri` from this URL: the one sent at login, never the raw request.
  const callbackUrl = createRouteUrl(config.routes.callback, appBaseUrl);
  callbackUrl.search = req.nextUrl.search;

  const dpopKeyPair = await getDpopKeyPair(config);
  const engine = await setup.getEngine();
  const onCallback = onCallbackOf(setup);

  let res: NextResponse | undefined;
  let hookFailed = false;
  let noIdToken = false;
  const loginOptions = {
    beforeSessionSaved: async (
      stateData: StateData,
      {
        idTokenClaims,
        anonymousSessionLinked: linked
      }: {
        idTokenClaims?: Record<string, unknown>;
        anonymousSessionLinked?: boolean;
      }
    ) => {
      anonymousSessionLinked = linked;
      // Nothing is saved without an identity: the engine would write a session with no user, or
      // keep the user of a session that is already there and attach the new tokens to it.
      if (!idTokenClaims) {
        noIdToken = true;
        throw new Error("The token response has no ID token.");
      }
      try {
        const session = setup.sessionMapper.toSessionData(stateData);
        res = await onCallback(null, callbackCtx(), session);
        const final = await finalizeSession(config, session, stateData.idToken);
        return setup.sessionMapper.toStateData(final);
      } catch (e) {
        hookFailed = true;
        throw e;
      }
    }
  };
  try {
    let result: InteractiveLoginResult | undefined;
    if (magicLink) {
      // The engine sends no DPoP proof on this exchange. Never in Enterprise Connect
      // mode: the engine refuses passwordless there, so no magic link was sent.
      await engine.completePasswordlessMagicLink(
        callbackUrl,
        ctx,
        undefined,
        loginOptions
      );
    } else {
      result = await engine.completeInteractiveLogin(
        callbackUrl,
        ctx,
        dpopKeyPair ? { dpopKeyPair } : undefined,
        loginOptions
      );
    }

    if (result && config.options.enterpriseConnect) {
      anonymousSessionLinked = result.anonymousSessionLinked;
      if (!result.idTokenClaims) {
        return handleCallbackError(
          noIdTokenError(),
          callbackCtx(),
          req,
          setup,
          identifier
        );
      }
      // Auth0 is only an SSO relay: no session is saved, so the hook did not run. `onCallback`
      // is the only way a cookie reaches the browser.
      try {
        res = await onCallback(
          null,
          callbackCtx(),
          enterpriseSession(
            setup,
            result,
            typeof config.domain === "function" ? transaction.domain : undefined
          )
        );
      } catch (e) {
        hookFailed = true;
        throw e;
      }
      if (!res) {
        console.warn(
          "[nextjs-auth0] onCallback returned a falsy value in Enterprise Connect mode. " +
            "Ensure your hook returns a NextResponse on all code paths — the response is the " +
            "only way a session cookie reaches the browser in this mode."
        );
        return res;
      }
    }
  } catch (e) {
    if (noIdToken) {
      return handleCallbackError(
        noIdTokenError(),
        callbackCtx(),
        req,
        setup,
        identifier
      );
    }
    // `onCallback` and `beforeSessionSaved` errors reach the app as thrown, as on nextjs.
    if (hookFailed) {
      throw e;
    }
    const error = await setup.errors.toSdkError(e, "callback", { callbackUrl });
    if (!(error instanceof SdkError)) {
      throw error;
    }
    return handleCallbackError(error, callbackCtx(), req, setup, identifier);
  }

  if (!res) {
    throw new InvalidConfigurationError(
      "The login finished without running the onCallback hook."
    );
  }
  // The session (or id) cookie and the transaction delete, written by the engine.
  transferCookies(scratch, res);
  if (!config.options.enterpriseConnect) {
    addCacheControlHeadersForSession(res);
  }
  return res;
}

/**
 * `onCallback` gets the error and returns the response; the transaction of this login is deleted
 * on it so it does not pile up.
 */
async function handleCallbackError(
  error: SdkError,
  ctx: OnCallbackContext,
  req: NextRequest,
  setup: EngineSetup,
  identifier?: string
): Promise<NextResponse> {
  const res = await onCallbackOf(setup)(error, ctx, null);
  if (identifier) {
    await setup.transactionStore.delete(
      identifier,
      middlewareContext(req, res)
    );
  }
  return res;
}

/**
 * nextjs's check of the `iss` in the callback URL, which the engine reports as any other request
 * failure. Static mode reads the issuer, and whether Auth0 always sends `iss`, from the discovery
 * document. Resolver mode has no access to it, so only a wrong `iss` is caught, against the
 * domain stored in the transaction. A discovery failure is left to the code exchange to report.
 */
async function hasWrongIssuer(
  setup: EngineSetup,
  req: NextRequest,
  transaction: TransactionData
): Promise<boolean> {
  const iss = req.nextUrl.searchParams.get("iss");
  if (typeof setup.config.domain !== "function") {
    try {
      const metadata = await (
        await setup.getEngine()
      ).authClient.getServerMetadata();
      return iss === null
        ? metadata.authorization_response_iss_parameter_supported === true
        : iss !== metadata.issuer;
    } catch {
      return false;
    }
  }
  if (iss === null || !transaction.domain) {
    return false;
  }
  try {
    return (
      normalizeDomain(iss).domain !== normalizeDomain(transaction.domain).domain
    );
  } catch {
    return true;
  }
}

/**
 * The transaction of this login and where it was read. A magic link has no PKCE verifier, and
 * the engine always stores it under the fixed identifier, so with parallel transactions on it is
 * looked for there when none is stored for the `state`.
 */
async function findTransaction(
  setup: EngineSetup,
  state: string | null,
  ctx: ReturnType<typeof middlewareContext>
): Promise<
  | { transaction: TransactionData; identifier: string; magicLink: boolean }
  | undefined
> {
  const identifier = transactionIdentifier(setup, state);
  const transaction = await readTransaction(setup, identifier, ctx);
  if (transaction) {
    return { transaction, identifier, magicLink: !transaction.codeVerifier };
  }

  const fixed = setup.config.transactionCookie.prefix;
  if (identifier === fixed) {
    return undefined;
  }
  const magicLink = await readTransaction(setup, fixed, ctx);
  return magicLink && !magicLink.codeVerifier
    ? { transaction: magicLink, identifier: fixed, magicLink: true }
    : undefined;
}

async function readTransaction(
  setup: EngineSetup,
  identifier: string,
  ctx: ReturnType<typeof middlewareContext>
): Promise<TransactionData | undefined> {
  try {
    return await setup.transactionStore.get(identifier, ctx);
  } catch {
    // A cookie that cannot be read is no transaction.
    return undefined;
  }
}

function transactionIdentifier(
  { config }: EngineSetup,
  state?: string | null
): string {
  const prefix = config.transactionCookie.prefix;
  return config.enableParallelTransactions && state
    ? `${prefix}${state}`
    : prefix;
}

/**
 * nextjs asks for an ID token when it exchanges the code (`requireIdToken`), so a response
 * without one is the same failure as any other bad code exchange.
 */
function noIdTokenError(): AuthorizationCodeGrantError {
  return new AuthorizationCodeGrantError({
    cause: new OAuth2Error({ code: "unknown_error" })
  });
}

/**
 * The session `onCallback` sees in Enterprise Connect mode. The engine keeps nothing there, so it
 * returns the login's tokens and the session ceiling, and the session is built from them as for
 * any other login: `mcd` only in resolver mode, from the domain of the login, and no refresh
 * token (Enterprise Connect clients get none).
 */
function enterpriseSession(
  setup: EngineSetup,
  result: InteractiveLoginResult,
  domain: string | undefined
): SessionData {
  return setup.sessionMapper.toSessionData({
    user: result.user,
    idToken: result.idToken,
    tokenSets: result.tokenSet ? [result.tokenSet] : [],
    ...(domain && { domain }),
    sessionExpiresAt: result.sessionExpiresAt,
    internal: {
      sid: result.idTokenClaims?.sid,
      createdAt: Math.floor(Date.now() / 1000)
    }
  } as StateData);
}

function onCallbackOf(setup: EngineSetup): OnCallbackHook {
  return setup.config.options.onCallback ?? defaultOnCallback;
}

const defaultOnCallback: OnCallbackHook = async (error, ctx) => {
  if (error) {
    return new NextResponse(error.message, { status: 500 });
  }
  if (!ctx.appBaseUrl) {
    throw new InvalidConfigurationError(
      "appBaseUrl could not be resolved for the callback redirect."
    );
  }
  return NextResponse.redirect(
    createRouteUrl(ctx.returnTo || "/", ctx.appBaseUrl).toString()
  );
};
