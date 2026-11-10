import { NextRequest, NextResponse } from "next/server.js";

import { MfaRequiredError } from "../../errors/index.js";
import type {
  AuthorizationParameters,
  ConnectAccountOptions
} from "../../types/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import { retrieveAccessToken } from "../auth/access-token.js";
import { issuerOf, startConnectAccount } from "../auth/connected-accounts.js";
import { readSession } from "../auth/session.js";
import { middlewareContext } from "../engine/adapters/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { toTokenSet } from "../fetcher/create-fetcher.js";
import { addCacheControlHeadersForSession } from "../utils/cache-control.js";

/**
 * Route: GET /auth/connect?connection=&returnTo=&scopes=, any other parameter sent to the provider
 * as an authorization parameter. nextjs's responses:
 * 1. no `connection`: 400; no session, or one for another domain: 401, text body
 * 2. the My Account API token: MFA required: 403 with the MFA body; any other token error: 401
 * 3. the ticket cannot be created: the My Account API status (else 500), text body
 * 4. otherwise the redirect to the provider, with the transaction cookie; no-cache when the
 *    session was refreshed
 *
 * The cookies the engine wrote (a refresh, MFA context) go on whichever response is returned.
 */
export async function handleConnectAccount(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  const scratch = NextResponse.next();
  const ctx = middlewareContext(req, scratch);
  const res = await connect(req, setup, ctx);
  transferCookies(scratch, res);
  return res;
}

async function connect(
  req: NextRequest,
  setup: EngineSetup,
  ctx: ReturnType<typeof middlewareContext>
): Promise<NextResponse> {
  const { state, error: sessionError } = await readSession(setup, ctx);

  // pass all query params except `connection`, `returnTo`, `scopes` as authorization params
  const { searchParams } = req.nextUrl;
  const connection = searchParams.get("connection");
  const returnTo = searchParams.get("returnTo") ?? undefined;
  const scopes = searchParams.getAll("scopes");
  const authorizationParams = Object.fromEntries(
    [...searchParams.entries()].filter(
      ([key]) => key !== "connection" && key !== "returnTo" && key !== "scopes"
    )
  ) as AuthorizationParameters;

  if (!connection) {
    return new NextResponse("A connection is required.", { status: 400 });
  }

  if (sessionError || !state) {
    return new NextResponse(
      sessionError?.message ?? "The user does not have an active session.",
      { status: 401 }
    );
  }

  const issuer = await issuerOf(setup, ctx);
  const result = await retrieveAccessToken(setup, ctx, {
    scope: "create:me:connected_accounts",
    audience: `${issuer}me/`
  });
  if (result.error) {
    // The session was saved again by `retrieveAccessToken`.
    if (result.error instanceof MfaRequiredError) {
      const res = NextResponse.json(result.error.toJSON(), { status: 403 });
      addCacheControlHeadersForSession(res);
      return res;
    }
    return new NextResponse(
      "Failed to retrieve a connected account access token.",
      { status: 401 }
    );
  }

  const options: ConnectAccountOptions = {
    connection,
    authorizationParams,
    returnTo,
    ...(scopes.length > 0 && { scopes })
  };
  const started = await startConnectAccount(setup, ctx, req, issuer, {
    ...options,
    token: toTokenSet(result.accessToken)
  });
  if (started.error) {
    return new NextResponse(started.error.message, {
      status: started.error.cause?.status ?? 500
    });
  }

  if (result.refreshed) {
    addCacheControlHeadersForSession(started.response);
  }
  return started.response;
}
