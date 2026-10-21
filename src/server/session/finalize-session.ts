import { InvalidConfigurationError } from "../../errors/index.js";
import type { SessionData } from "../../types/index.js";
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
