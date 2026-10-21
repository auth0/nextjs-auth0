import { NextRequest, NextResponse } from "next/server.js";
import { RequestCookies, ResponseCookies } from "@edge-runtime/cookies";

import type { SessionData } from "../../types/index.js";
import { sharedJarContext, type CookieContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import {
  toHeadersFromIncomingMessage,
  toNextRequest,
  toNextResponse,
  toUrlFromPagesRouter
} from "../http/next-compat.js";
import { setPagesRouterCookies } from "../http/pages-router.js";
import type {
  PagesRouterRequest,
  PagesRouterResponse
} from "../types/index.js";
import { getSession } from "./get-session.js";

/**
 * Replaces the session of the signed-in user, keeping the SDK's own `internal` (id, created time,
 * domain, ceiling). The three call forms and their errors are `main`'s.
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
