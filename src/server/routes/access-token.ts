import { NextRequest, NextResponse } from "next/server.js";

import { MfaRequiredError } from "../../errors/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import { middlewareContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { addCacheControlHeadersForSession } from "../http/cache-control.js";
import { retrieveAccessToken } from "../token/get-access-token.js";

/**
 * Route: GET /auth/access-token?audience=&scope=&mergeScopes=. `getAccessToken` for the browser,
 * with `main`'s responses: 200 with the token, 403 with the MFA body, 401 with
 * `{ error: { message, code } }` for any other token error. The cookies the engine wrote (a
 * refresh, a session expired) are put on the response.
 */
export async function handleAccessToken(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  const { searchParams } = req.nextUrl;
  const scratch = NextResponse.next();
  const result = await retrieveAccessToken(
    setup,
    middlewareContext(req, scratch),
    {
      audience: searchParams.get("audience"),
      scope: searchParams.get("scope"),
      // Only "false" turns merging off.
      mergeScopes:
        searchParams.get("mergeScopes") === "false" ? false : undefined
    }
  );

  let res: NextResponse;
  if (result.error instanceof MfaRequiredError) {
    // The session saved again by `retrieveAccessToken`.
    res = NextResponse.json(result.error.toJSON(), { status: 403 });
    addCacheControlHeadersForSession(res);
  } else if (result.error) {
    // On `session_expired` the engine deleted the stored session; the delete goes out here.
    res = NextResponse.json(
      { error: { message: result.error.message, code: result.error.code } },
      { status: 401 }
    );
  } else {
    const { accessToken, refreshed } = result;
    const expiresIn = Math.max(
      0,
      accessToken.expiresAt - Math.floor(Date.now() / 1000)
    );
    res = NextResponse.json({
      token: accessToken.token,
      scope: accessToken.scope,
      expires_at: accessToken.expiresAt,
      expires_in: expiresIn,
      ...(accessToken.token_type && { token_type: accessToken.token_type })
    });
    // As on `main`: no-cache only when the session cookie changed.
    if (refreshed) {
      addCacheControlHeadersForSession(res);
    }
  }

  transferCookies(scratch, res);
  return res;
}
