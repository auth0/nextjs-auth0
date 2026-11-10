import type { GetAccessTokenHooks } from "@auth0/auth0-server-js";

import { InvalidConfigurationError } from "../../errors/index.js";
import type { SessionData, User } from "../../types/index.js";
import type { Engine, EngineSetup } from "../engine/create-engine.js";
import type { EngineConfig } from "../engine/resolve-config.js";
import { filterDefaultIdTokenClaims } from "../user.js";

/**
 * What is saved at login: the `beforeSessionSaved` result, or the session with the default ID
 * token claims. `internal` is always the one the SDK built.
 */
export async function finalizeSession(
  config: EngineConfig,
  session: SessionData,
  idToken?: string
): Promise<SessionData> {
  const hook = config.options.beforeSessionSaved;
  let final: SessionData;
  if (hook) {
    final = {
      ...(await hook(session, idToken ?? null)),
      internal: session.internal
    };
  } else {
    final = { ...session, user: filterDefaultIdTokenClaims(session.user) };
  }

  // A hook must not remove the domain record that keeps sessions apart in resolver mode.
  if (typeof config.domain === "function" && !final.internal?.mcd) {
    throw new InvalidConfigurationError(
      "beforeSessionSaved hook must not remove the internal.mcd field in resolver mode. " +
        "The internal.mcd object is required for multi-custom-domain session isolation. " +
        "If you need to modify session.internal, preserve the .mcd field."
    );
  }
  return final;
}

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
 *
 * `noIdToken`: the error for a login that would be saved with no user (no session before and no
 * ID token in the response). Nothing is saved; the error reaches the caller unchanged, as `failed`
 * says. Without it, such a login is not handled here.
 */
export function createLoginHook(
  { config, sessionMapper }: EngineSetup,
  { noIdToken }: { noIdToken?: () => Error } = {}
): LoginHook {
  let failed = false;
  return {
    beforeSessionSaved: async (stateData) => {
      try {
        if (noIdToken && !stateData.user) {
          throw noIdToken();
        }
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

export interface RefreshHook {
  /**
   * For the engine's `beforeSessionSaved` on a refresh: the new ID token claims go to `user`,
   * then `beforeSessionSaved` (or the default claim filter) runs, as on nextjs.
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
