import type { NextRequest, NextResponse } from "next/server.js";

import {
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode
} from "../../errors/index.js";
import {
  SUBJECT_TOKEN_TYPES,
  type AccessTokenForConnectionOptions
} from "../../types/index.js";
import { getDpopKeyPair } from "../dpop/dpop-key-pair.js";
import { withCallContext } from "../engine/adapters/call-context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import type {
  PagesRouterRequest,
  PagesRouterResponse
} from "../types/index.js";
import { readSession } from "./session.js";

/**
 * `getAccessTokenForConnection(options)` and `(options, req, res)`: a token for an external
 * provider held in Auth0 Token Vault. The engine finds the cached token for the connection and
 * `login_hint`, exchanges the session token at Auth0 when needed, saves the session, and removes
 * an expired token when the exchange fails. Around it, nextjs's rules:
 * 1. the session is read without the session ceiling (connection tokens follow the provider's
 *    lifetime); none: `missing_session`; resolver mode, stored for another domain: the
 *    `SessionDomainMismatchError`
 * 2. `subject_token_type` set to the access token type sends the session access token
 * 3. the errors are nextjs's codes and texts
 */
export async function getAccessTokenForConnection(
  setup: EngineSetup,
  options: AccessTokenForConnectionOptions,
  req: PagesRouterRequest | NextRequest | undefined,
  res: PagesRouterResponse | NextResponse | undefined
): Promise<{ token: string; expiresAt: number; scope?: string }> {
  return withCallContext(req, res, async (ctx) => {
    const { state, error } = await readSession(setup, ctx, {
      skipCeilingCheck: true
    });
    if (error) {
      throw error;
    }
    if (!state) {
      throw new AccessTokenForConnectionError(
        AccessTokenForConnectionErrorCode.MISSING_SESSION,
        "The user does not have an active session."
      );
    }

    const dpopKeyPair = await getDpopKeyPair(setup.config);
    const tokenSet = await setup.errors.callEngine(
      "connectionToken",
      async () =>
        (await setup.getEngine()).getAccessTokenForConnection(
          {
            connection: options.connection,
            loginHint: options.login_hint || undefined,
            ...(options.subject_token_type ===
              SUBJECT_TOKEN_TYPES.SUBJECT_TYPE_ACCESS_TOKEN && {
              subjectTokenType: SUBJECT_TOKEN_TYPES.SUBJECT_TYPE_ACCESS_TOKEN
            })
          },
          ctx,
          dpopKeyPair ? { dpopKeyPair } : undefined
        )
    );

    return {
      token: tokenSet.accessToken,
      scope: tokenSet.scope,
      expiresAt: tokenSet.expiresAt
    };
  });
}
