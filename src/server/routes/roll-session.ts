import { NextRequest, NextResponse } from "next/server.js";

import { SessionDomainMismatchError } from "../../errors/index.js";
import { middlewareContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { addCacheControlHeadersForSession } from "../http/cache-control.js";
import { readSession } from "../session/read-session.js";

/**
 * A request that matches no SDK route continues to the app. When rolling is on, the session is
 * saved again first: the store recomputes the expiry on every save, which pushes it forward.
 */
export async function rollSession(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  const res = NextResponse.next();
  if (!(await shouldRollSession(req, setup))) {
    return res;
  }

  const ctx = middlewareContext(req, res);
  const { state, error } = await readSession(setup, ctx);
  if (error instanceof SessionDomainMismatchError) {
    console.warn(`[nextjs-auth0] ${error.message}`);
  }
  if (!error && state) {
    // The stored state keeps `internal.createdAt`, which the store needs to compute the expiry.
    await setup.sessionStore.set(
      setup.config.sessionCookie.name,
      state,
      false,
      ctx
    );
    addCacheControlHeadersForSession(res);
  }
  return res;
}

/**
 * Rolling on (default `true`) and `beforeSessionRolled` allowing it. A hook that throws rolls the
 * session, as on nextjs.
 */
async function shouldRollSession(
  req: NextRequest,
  setup: EngineSetup
): Promise<boolean> {
  const session = setup.config.options.session;
  // Default only when the option is `undefined`, as nextjs and the engine's store do: a `null` from
  // an untyped caller turns rolling off.
  const rolling =
    session?.rolling === undefined ? true : Boolean(session.rolling);
  if (!rolling) {
    return false;
  }
  if (!session?.beforeSessionRolled) {
    return true;
  }
  try {
    return await session.beforeSessionRolled(req);
  } catch (e) {
    console.warn(
      "The beforeSessionRolled hook threw an error. Defaulting to rolling the session.",
      e
    );
    return true;
  }
}
