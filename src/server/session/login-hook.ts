import type { Engine, EngineSetup } from "../engine/create-engine.js";
import { finalizeSession } from "./finalize-session.js";

// The engine's `CompleteLoginOptions` (not exported by the engine).
type CompleteLoginOptions = NonNullable<Parameters<Engine["mfa"]["verify"]>[3]>;

export interface LoginHook {
  /**
   * For the engine's `beforeSessionSaved` on a login without the redirect callback (MFA verify,
   * passkey, passwordless): `beforeSessionSaved` (or the default claim filter) runs on the session
   * the engine built, as the callback's does.
   */
  beforeSessionSaved: NonNullable<CompleteLoginOptions["beforeSessionSaved"]>;
  /**
   * `true` when the hook threw. The error is the app's, so it is passed through unchanged.
   */
  readonly failed: boolean;
}

/**
 * The hook for one engine call that logs the user in and saves the session.
 */
export function createLoginHook({
  config,
  sessionMapper
}: EngineSetup): LoginHook {
  let failed = false;
  return {
    beforeSessionSaved: async (stateData) => {
      try {
        const session = sessionMapper.toSessionData(stateData);
        const final = await finalizeSession(config, session, stateData.idToken);
        return sessionMapper.toStateData(final);
      } catch (e) {
        failed = true;
        throw e;
      }
    },
    get failed() {
      return failed;
    }
  };
}
