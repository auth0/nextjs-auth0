import { NextRequest, NextResponse } from "next/server.js";

import type { StartInteractiveLoginOptions } from "../../types/index.js";
import { parseNonNegativeIntegerParam } from "../../utils/authorization-params-helpers.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { startLogin } from "../login/start-login.js";

/**
 * Route: GET /auth/login. The query is the login options: `returnTo`, `challengeMode`, and every
 * other key is an authorization parameter.
 */
export async function handleLogin(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  const searchParams = Object.fromEntries(req.nextUrl.searchParams.entries());

  // The challenge mode is ours, not an authorization parameter.
  const queryChallengeMode = searchParams.challengeMode;
  delete searchParams.challengeMode;

  if (
    queryChallengeMode &&
    queryChallengeMode !== "popup" &&
    queryChallengeMode !== "redirect"
  ) {
    return new NextResponse(
      `Invalid challengeMode query param: ${queryChallengeMode}. Expected 'redirect', 'popup', or omit.`,
      { status: 400 }
    );
  }

  // The popup callback returns a page for the opener window, which an Enterprise Connect app never
  // gets: its own session cookie is set by `onCallback`.
  if (
    setup.config.options.enterpriseConnect &&
    queryChallengeMode === "popup"
  ) {
    return new NextResponse(
      "challengeMode=popup is not supported in Enterprise Connect mode.",
      { status: 400 }
    );
  }

  if (
    searchParams.max_age !== undefined &&
    parseNonNegativeIntegerParam("max_age", searchParams.max_age) === null
  ) {
    return new NextResponse(
      `Invalid max_age query param: "${searchParams.max_age}". Must be a non-negative integer.`,
      { status: 400 }
    );
  }

  // `returnTo` is not an authorization parameter.
  const { returnTo, ...authorizationParameters } = searchParams;

  const options: StartInteractiveLoginOptions = {
    authorizationParameters,
    returnTo,
    challengeMode: queryChallengeMode as "redirect" | "popup" | undefined
  };
  return startLogin(setup, options, req);
}
