import type { GetAccessTokenHooks } from "@auth0/auth0-server-js";

import type { User } from "../../types/index.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { finalizeSession } from "../session/finalize-session.js";

export interface RefreshHook {
  /**
   * For the engine's `beforeSessionSaved` on a refresh: the new ID token claims go to `user`,
   * then `beforeSessionSaved` (or the default claim filter) runs, as on `main`.
   */
  beforeSessionSaved: NonNullable<GetAccessTokenHooks["beforeSessionSaved"]>;
  /**
   * `true` once the refreshed session was handed back to the engine to be saved.
   */
  readonly ran: boolean;
  /**
   * `true` when the hook threw. The error is the app's, so it is passed through unchanged.
   */
  readonly failed: boolean;
}

/**
 * The hook for one engine call that may refresh the session (`getAccessToken`, session transfer).
 */
export function createRefreshHook({
  config,
  sessionMapper
}: EngineSetup): RefreshHook {
  let ran = false;
  let failed = false;
  return {
    beforeSessionSaved: async (stateData, { idTokenClaims }) => {
      try {
        const session = sessionMapper.toSessionData(stateData);
        if (idTokenClaims) {
          session.user = idTokenClaims as User;
        }
        const final = await finalizeSession(config, session, stateData.idToken);
        ran = true;
        return sessionMapper.toStateData(final);
      } catch (e) {
        failed = true;
        throw e;
      }
    },
    get ran() {
      return ran;
    },
    get failed() {
      return failed;
    }
  };
}
