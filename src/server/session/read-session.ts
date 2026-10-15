import type { StateData } from "@auth0/auth0-server-js";
import { decodeJwt } from "jose";

import { SessionDomainMismatchError } from "../../errors/index.js";
import { normalizeDomain } from "../../utils/normalize.js";
import { isSessionCeilingReached } from "../../utils/session-helpers.js";
import type { CookieContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { NextStatefulStateStore } from "../engine/stores/stateful-state-store.js";

export interface ReadSessionResult {
  state?: StateData;
  error?: SessionDomainMismatchError;
}

/**
 * Reads the stored session with `main`'s checks (`getSessionWithDomainCheck`), keeping `internal`
 * so the state can be saved again:
 * 1. no session stored: no session
 * 2. session ceiling reached: no session, and the stateful row is deleted
 * 3. stored for another domain: no session and a `SessionDomainMismatchError`, in static mode too
 * 4. no domain stored, static mode: returned as is
 * 5. no domain stored, resolver mode: the domain is taken from the ID token `iss`, else the
 *    current domain, and set on the returned state only (saved by the caller, if it saves)
 */
export async function readSession(
  setup: EngineSetup,
  ctx: CookieContext
): Promise<ReadSessionResult> {
  const { sessionStore, config } = setup;
  const state = await sessionStore.get(config.sessionCookie.name, ctx);
  if (!state) {
    return {};
  }

  if (isSessionCeilingReached(state.sessionExpiresAt)) {
    // Stateless sessions live in the cookie only, so there is nothing to delete.
    if (sessionStore instanceof NextStatefulStateStore) {
      sessionStore
        .deleteByReqCookies(config.sessionCookie.name, ctx.reqCookies)
        .catch((e) =>
          console.warn("[auth0] Failed to delete session on ceiling expiry:", e)
        );
    }
    return {};
  }

  if (state.domain) {
    const currentDomain = await setup.currentDomain(ctx);
    if (state.domain !== currentDomain) {
      return {
        error: new SessionDomainMismatchError(
          `Session was created for domain '${state.domain}' but the current request is for domain '${currentDomain}'. ` +
            `This may indicate a cross-domain session reuse attempt.`
        )
      };
    }
    return { state };
  }

  // Static mode: no domain is stored, which keeps the cookie small (`main` #2595).
  if (typeof config.domain !== "function") {
    return { state };
  }

  // Resolver mode, a session written before MCD was turned on: the ID token `iss` always gives the
  // same domain for the same session.
  let inferredDomain: string | undefined;
  if (state.idToken) {
    try {
      const { iss } = decodeJwt(state.idToken);
      if (typeof iss === "string") {
        inferredDomain = normalizeDomain(iss).domain;
      }
    } catch {
      // Malformed ID token or issuer: fall back to the current domain.
    }
  }
  state.domain = inferredDomain ?? (await setup.currentDomain(ctx));
  return { state };
}
