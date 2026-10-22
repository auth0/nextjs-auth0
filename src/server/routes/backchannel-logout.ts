import { NextRequest, NextResponse } from "next/server.js";
import { decodeJwt } from "jose";

import { BackchannelLogoutError, DiscoveryError } from "../../errors/index.js";
import { normalizeDomain } from "../../utils/normalize.js";
import { readContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { NextStatefulStateStore } from "../engine/stores/stateful-state-store.js";

/**
 * Route: POST /auth/backchannel-logout. Auth0 posts a `logout_token`; the engine verifies it and
 * calls the session store's `deleteByLogoutToken({ sid, sub, iss })`. nextjs's checks and
 * responses around it:
 * - no session store, or one without `deleteByLogoutToken`: 500
 * - no token: 400
 * - token issuer for another domain: 403 (resolver mode: 400 when it has no issuer)
 * - token that does not verify: 400 with the reason
 * - resolver mode, anything else that fails: logged, 400 "Failed to process logout token."
 * - done: 204
 */
export async function handleBackChannelLogout(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  const { config } = setup;
  if (!(setup.sessionStore instanceof NextStatefulStateStore)) {
    return new NextResponse("A session data store is not configured.", {
      status: 500
    });
  }
  if (!config.options.sessionStore?.deleteByLogoutToken) {
    return new NextResponse(
      "Back-channel logout is not supported by the session data store.",
      { status: 500 }
    );
  }

  const body = new URLSearchParams(await req.text());
  const logoutToken = body.get("logout_token");
  if (!logoutToken) {
    return new NextResponse("Missing `logout_token` in the request body.", {
      status: 400
    });
  }

  const { ctx } = await readContext(req);
  const verifyAndDelete = async (): Promise<NextResponse> => {
    try {
      await setup.errors.callEngine("backchannelLogout", async () =>
        (await setup.getEngine()).handleBackchannelLogout(logoutToken, ctx)
      );
    } catch (e) {
      if (e instanceof BackchannelLogoutError || e instanceof DiscoveryError) {
        return textResponse(e.message, 400);
      }
      throw e;
    }
    return new NextResponse(null, { status: 204 });
  };

  if (typeof config.domain === "function") {
    // Resolver mode: the domain resolved for the request is the trust anchor. The token's issuer
    // is read without verifying, only to compare it.
    try {
      const issuerDomain = readIssuerDomain(logoutToken);
      if (!issuerDomain) {
        return textResponse("Missing 'iss' claim in logout token.", 400);
      }
      if (issuerDomain !== (await setup.currentDomain(ctx))) {
        return textResponse(
          "Logout token issuer does not match the resolved domain.",
          403
        );
      }
      return await verifyAndDelete();
    } catch (e) {
      console.error(
        `Unexpected error in backchannel logout: ${
          e instanceof Error ? e.message : String(e)
        }`
      );
      return textResponse("Failed to process logout token.", 400);
    }
  }

  // Static mode: custom domains of one tenant share signing keys, so a token for another domain
  // would verify. An issuer that cannot be read skips the check; verification decides.
  const issuerDomain = readIssuerDomain(logoutToken);
  if (issuerDomain && issuerDomain !== (await setup.currentDomain(ctx))) {
    return textResponse(
      "Logout token issuer does not match the configured domain.",
      403
    );
  }
  // A store error is thrown, as on nextjs.
  return verifyAndDelete();
}

/**
 * The normalized domain of the token's `iss`, read without verifying; `undefined` when the token
 * does not decode or the issuer is missing or not a valid domain.
 */
function readIssuerDomain(logoutToken: string): string | undefined {
  try {
    const { iss } = decodeJwt(logoutToken);
    return typeof iss === "string" && iss
      ? normalizeDomain(iss).domain
      : undefined;
  } catch {
    return undefined;
  }
}

function textResponse(message: string, status: number): NextResponse {
  return new NextResponse(message, {
    status,
    headers: { "Content-Type": "text/plain" }
  });
}
