import {
  TokenRevocationError,
  TokenRevocationErrorCode
} from "../../errors/index.js";
import { readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { readSession } from "../session/read-session.js";
import type { PagesRouterRequest } from "../types/index.js";

/**
 * Revokes the session's refresh token at Auth0, with `main`'s errors: no session, a session stored
 * for another domain (`SessionDomainMismatchError`), no refresh token. The session is not changed
 * and no cookie is written.
 */
export async function revokeRefreshToken(
  setup: EngineSetup,
  input?: Request | PagesRouterRequest
): Promise<void> {
  const { ctx } = await readContext(input);
  const { state, error } = await readSession(setup, ctx);
  if (error) {
    throw error;
  }
  if (!state) {
    throw new TokenRevocationError(
      TokenRevocationErrorCode.MISSING_SESSION,
      "The user does not have an active session."
    );
  }
  if (!state.refreshToken?.trim()) {
    throw new TokenRevocationError(
      TokenRevocationErrorCode.MISSING_REFRESH_TOKEN,
      "The session does not contain a refresh token to revoke."
    );
  }

  const { refreshToken } = state;
  // Passed explicitly, so in static mode the engine does not read the session again.
  await setup.errors.callEngine("revoke", async () =>
    (await setup.getEngine()).revokeRefreshToken({ token: refreshToken }, ctx)
  );
}
