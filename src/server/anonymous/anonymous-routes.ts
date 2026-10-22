import { NextRequest, NextResponse } from "next/server.js";

import {
  AnonymousSessionError,
  getStatusForAnonymousError,
  mapAnonymousErrorCode
} from "../../errors/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import { middlewareContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { addCacheControlHeadersForSession } from "../http/cache-control.js";
import {
  fetchAnonymousSession,
  isAnonymousSessionEnabled
} from "./anonymous-operations.js";

/**
 * Route: GET /auth/anonymous-session. 200 with `{ id, accessToken, expiresAt, metadata? }`, or
 * 204 when there is none; the engine renews an expired token first. Errors: nextjs's
 * `{ error, error_description }` and status. The cookies the engine wrote (a renewed token, a
 * deleted session) go on every response.
 */
export async function handleAnonymousSession(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  if (!isAnonymousSessionEnabled(setup)) {
    return notFound();
  }

  const scratch = NextResponse.next();
  let res: NextResponse;
  try {
    const session = await fetchAnonymousSession(
      setup,
      middlewareContext(req, scratch)
    );
    res = session
      ? NextResponse.json(session)
      : new NextResponse(null, { status: 204 });
  } catch (e) {
    const code = e instanceof AnonymousSessionError ? e.code : "server_error";
    res = NextResponse.json(
      { error: code, error_description: mapAnonymousErrorCode(code).message },
      { status: getStatusForAnonymousError(code) }
    );
  }
  transferCookies(scratch, res);
  addCacheControlHeadersForSession(res);
  return res;
}

/**
 * Route: POST /auth/anonymous-session/logout. The engine deletes the anonymous cookie; no
 * request to Auth0. Always 200 with `{ ok: true }`, as on nextjs.
 */
export async function handleAnonymousSessionLogout(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  if (!isAnonymousSessionEnabled(setup)) {
    return notFound();
  }

  const res = NextResponse.json({ ok: true });
  try {
    const engine = await setup.getEngine();
    await engine.anonymous.logout(middlewareContext(req, res));
  } catch (err) {
    console.warn(
      "[nextjs-auth0] Anonymous logout failed (ignored):",
      err instanceof Error ? err.message : String(err)
    );
  }
  addCacheControlHeadersForSession(res);
  return res;
}

function notFound(): NextResponse {
  return new NextResponse("Not found", { status: 404 });
}
