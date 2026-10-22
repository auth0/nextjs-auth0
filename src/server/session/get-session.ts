import type { SessionData } from "../../types/index.js";
import { readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import type { PagesRouterRequest } from "../types/index.js";
import { readSession } from "./read-session.js";

/**
 * The session of the current request, or `null`. A session stored for another domain throws
 * `SessionDomainMismatchError`, as on nextjs. A read never writes a cookie.
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
