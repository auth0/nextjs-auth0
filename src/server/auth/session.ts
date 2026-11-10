import { NextRequest, NextResponse } from "next/server.js";
import type { StateData } from "@auth0/auth0-server-js";
import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";
import { decodeJwt } from "jose";

import { SessionDomainMismatchError } from "../../errors/index.js";
import type { SessionData } from "../../types/index.js";
import { normalizeDomain } from "../../utils/normalize.js";
import { isSessionCeilingReached } from "../../utils/session-helpers.js";
import {
  readContext,
  sharedJarContext,
  type CookieContext
} from "../engine/adapters/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { NextStatefulStateStore } from "../engine/stores/stateful-state-store.js";
import type {
  PagesRouterRequest,
  PagesRouterResponse
} from "../types/index.js";
import {
  toHeadersFromIncomingMessage,
  toNextRequest,
  toNextResponse,
  toUrlFromPagesRouter
} from "../utils/next-compat.js";
import { setPagesRouterCookies } from "../utils/pages-router.js";

export interface ReadSessionResult {
  state?: StateData;
  error?: SessionDomainMismatchError;
}

/**
 * Reads the stored session with nextjs's checks (`getSessionWithDomainCheck`), keeping `internal`
 * so the state can be saved again:
 * 1. no session stored: no session
 * 2. session ceiling reached: no session, and the stateful row is deleted
 * 3. static mode (one fixed domain, also when it is read later from `AUTH0_DOMAIN`): returned as is.
 *    As in the engine, the domain stored in the session is not compared with the configured one,
 *    and a refresh goes to the stored domain
 * 4. resolver mode, stored for another domain: no session and a `SessionDomainMismatchError`
 * 5. resolver mode, no domain stored: the domain is taken from the ID token `iss`, else the
 *    current domain, and set on the returned state only (saved by the caller, if it saves)
 *
 * `skipCeilingCheck` skips step 2 only, for connection tokens: they follow the upstream provider's
 * lifetime, not the session ceiling.
 */
export async function readSession(
  setup: EngineSetup,
  ctx: CookieContext,
  { skipCeilingCheck = false }: { skipCeilingCheck?: boolean } = {}
): Promise<ReadSessionResult> {
  const { sessionStore, config } = setup;
  const state = await sessionStore.get(config.sessionCookie.name, ctx);
  if (!state) {
    return {};
  }

  if (!skipCeilingCheck && isSessionCeilingReached(state.sessionExpiresAt)) {
    // Stateless sessions live in the cookie only, so there is nothing to delete.
    if (sessionStore instanceof NextStatefulStateStore) {
      sessionStore
        .deleteByReqCookies(config.sessionCookie.name, ctx.reqCookies)
        .catch((e) =>
          console.warn("[auth0] Failed to delete session on ceiling expiry:", e)
        );
    }
    return {};
  }

  if (typeof config.domain !== "function") {
    return { state };
  }

  if (state.domain) {
    const currentDomain = await setup.currentDomain(ctx);
    if (state.domain !== currentDomain) {
      return {
        error: new SessionDomainMismatchError(
          `Session was created for domain '${state.domain}' but the current request is for domain '${currentDomain}'. ` +
            `This may indicate a cross-domain session reuse attempt.`
        )
      };
    }
    return { state };
  }

  // A session written before MCD was turned on: the ID token `iss` always gives the
  // same domain for the same session.
  let inferredDomain: string | undefined;
  if (state.idToken) {
    try {
      const { iss } = decodeJwt(state.idToken);
      if (typeof iss === "string") {
        inferredDomain = normalizeDomain(iss).domain;
      }
    } catch {
      // Malformed ID token or issuer: fall back to the current domain.
    }
  }
  state.domain = inferredDomain ?? (await setup.currentDomain(ctx));
  return { state };
}

/**
 * The session of the current request, or `null`. A session stored for another domain throws
 * `SessionDomainMismatchError` in resolver mode, as on nextjs. A read never writes a cookie.
 */
export async function getSession(
  setup: EngineSetup,
  input?: Request | PagesRouterRequest
): Promise<SessionData | null> {
  const { ctx } = await readContext(input);
  const { state, error } = await readSession(setup, ctx);
  if (error) {
    throw error;
  }
  return state ? setup.sessionMapper.toSessionData(state) : null;
}

/**
 * Replaces the session of the signed-in user, keeping the SDK's own `internal` (id, created time,
 * domain, ceiling). The three call forms and their errors are nextjs's.
 */
export async function updateSession(
  setup: EngineSetup,
  reqOrSession: PagesRouterRequest | NextRequest | Request | SessionData,
  res?: PagesRouterResponse | NextResponse | Response,
  sessionData?: SessionData
): Promise<void> {
  // A plain Request / Response (Next 16 Node runtime) is converted first.
  if (
    reqOrSession instanceof Request &&
    !(reqOrSession instanceof NextRequest)
  ) {
    reqOrSession = toNextRequest(reqOrSession);
  }
  if (res && res instanceof Response && !(res instanceof NextResponse)) {
    res = toNextResponse(res);
  }

  if (!res) {
    // App Router: Server Actions, Route Handlers.
    const existing = await getSession(setup);
    if (!existing) {
      throw new Error("The user is not authenticated.");
    }
    const updated = reqOrSession as SessionData;
    if (!updated) {
      throw new Error("The session data is missing.");
    }
    await save(setup, await sharedJarContext(), updated, existing);
    return;
  }

  const req = reqOrSession as PagesRouterRequest | NextRequest;
  if (!sessionData) {
    throw new Error("The session data is missing.");
  }
  const existing = await getSession(setup, req);
  if (!existing) {
    throw new Error("The user is not authenticated.");
  }

  if (req instanceof NextRequest && res instanceof NextResponse) {
    // Middleware.
    await save(
      setup,
      {
        reqCookies: req.cookies,
        resCookies: res.cookies,
        headers: req.headers,
        url: req.nextUrl
      },
      sessionData,
      existing
    );
    return;
  }

  // Pages Router: the cookies are written to a holder, then copied onto the response.
  const written = new Headers();
  const headers = toHeadersFromIncomingMessage(req as PagesRouterRequest);
  await save(
    setup,
    {
      reqCookies: new RequestCookies(headers),
      resCookies: new ResponseCookies(written),
      headers,
      url: toUrlFromPagesRouter(req as PagesRouterRequest)
    },
    sessionData,
    existing
  );
  setPagesRouterCookies(res as PagesRouterResponse, written);
}

async function save(
  setup: EngineSetup,
  ctx: CookieContext,
  session: SessionData,
  existing: SessionData
): Promise<void> {
  const state = setup.sessionMapper.toStateData({
    ...session,
    internal: { ...existing.internal }
  });
  await setup.sessionStore.set(
    setup.config.sessionCookie.name,
    state,
    false,
    ctx
  );
}
