import { NextRequest, NextResponse } from "next/server.js";

import { readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { addCacheControlHeadersForSession } from "../http/cache-control.js";
import { readSession } from "../session/read-session.js";

/**
 * Route: GET /auth/profile. The stored `user` as JSON. No session, or one stored for another
 * domain, is 401 (or 204 with `noContentProfileResponseWhenUnauthenticated`).
 */
export async function handleProfile(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  const { ctx } = await readContext(req);
  const { state, error } = await readSession(setup, ctx);

  if (error || !state) {
    return new NextResponse(null, {
      status: setup.config.options.noContentProfileResponseWhenUnauthenticated
        ? 204
        : 401
    });
  }

  const res = NextResponse.json(setup.sessionMapper.toSessionData(state).user);
  addCacheControlHeadersForSession(res);
  return res;
}
