import { NextRequest, NextResponse } from "next/server.js";

import { removeTrailingSlash } from "../../utils/pathUtils.js";
import { isNonNavigationalRequest } from "../../utils/request.js";
import {
  handleAnonymousSession,
  handleAnonymousSessionLogout
} from "../anonymous/anonymous-routes.js";
import type { EngineSetup } from "../engine/create-engine.js";
import type { EngineConfig } from "../engine/resolve-config.js";
import {
  handleMfaAssociate,
  handleMfaAuthenticators,
  handleMfaChallenge,
  handleMfaVerify
} from "../mfa/mfa-routes.js";
import {
  handlePasskeyChallenge,
  handlePasskeyEnrollmentChallenge,
  handlePasskeyEnrollmentVerify,
  handlePasskeyGetToken,
  handlePasskeyRegister
} from "../passkey/passkey-routes.js";
import {
  handlePasswordlessDbGetToken,
  handlePasswordlessDbOtpChallenge,
  handlePasswordlessStart,
  handlePasswordlessVerify
} from "../passwordless/passwordless-routes.js";
import type { Routes } from "../types/routes.js";
import { handleAccessToken } from "./access-token.js";
import { handleBackChannelLogout } from "./backchannel-logout.js";
import { handleCallback } from "./callback.js";
import { handleFederatedDomain } from "./federated-domain.js";
import { handleLogin } from "./login.js";
import { handleLogout } from "./logout.js";
import { handleProfile } from "./profile.js";
import { handleMyAccount, handleMyOrg } from "./proxy.js";
import { rollSession } from "./roll-session.js";

type RouteHandler = (
  req: NextRequest,
  setup: EngineSetup
) => Promise<NextResponse>;

interface RouteEntry {
  /**
   * The HTTP method; absent for any method.
   */
  method?: "GET" | "POST";
  /**
   * A configured route (`routes[key]`), or a fixed path prefix.
   */
  route: { key: keyof Routes } | { prefix: string };
  /**
   * When set, the route counts only when it returns `true`; otherwise the request falls through.
   */
  enabled?: (config: EngineConfig) => boolean;
  handle: RouteHandler;
}

// Replaced route by route in 3.4.
const notImplemented: RouteHandler = async () =>
  NextResponse.json({ error: "not_implemented" }, { status: 501 });

// nextjs's order (`auth-client.ts` `handler`): the first match wins.
const ROUTES: RouteEntry[] = [
  { method: "GET", route: { key: "login" }, handle: handleLogin },
  { method: "GET", route: { key: "logout" }, handle: handleLogout },
  { method: "GET", route: { key: "callback" }, handle: handleCallback },
  { method: "GET", route: { key: "profile" }, handle: handleProfile },
  {
    method: "GET",
    route: { key: "accessToken" },
    enabled: (config) => config.enableAccessTokenEndpoint,
    handle: handleAccessToken
  },
  {
    method: "POST",
    route: { key: "federatedDomain" },
    enabled: (config) => !!config.options.enterpriseConnect,
    handle: handleFederatedDomain
  },
  {
    method: "POST",
    route: { key: "backChannelLogout" },
    handle: handleBackChannelLogout
  },
  {
    method: "GET",
    route: { key: "connectAccount" },
    enabled: (config) => config.enableConnectAccountEndpoint,
    handle: notImplemented
  },
  {
    method: "GET",
    route: { key: "mfaAuthenticators" },
    handle: handleMfaAuthenticators
  },
  {
    method: "POST",
    route: { key: "mfaChallenge" },
    handle: handleMfaChallenge
  },
  {
    method: "POST",
    route: { key: "mfaAssociate" },
    handle: handleMfaAssociate
  },
  { method: "POST", route: { key: "mfaVerify" }, handle: handleMfaVerify },
  {
    method: "POST",
    route: { key: "passwordlessStart" },
    handle: handlePasswordlessStart
  },
  {
    method: "POST",
    route: { key: "passwordlessVerify" },
    handle: handlePasswordlessVerify
  },
  {
    method: "POST",
    route: { key: "passwordlessDbOtpChallenge" },
    handle: handlePasswordlessDbOtpChallenge
  },
  {
    method: "POST",
    route: { key: "passwordlessDbGetToken" },
    handle: handlePasswordlessDbGetToken
  },
  {
    method: "POST",
    route: { key: "passkeyRegister" },
    handle: handlePasskeyRegister
  },
  {
    method: "POST",
    route: { key: "passkeyChallenge" },
    handle: handlePasskeyChallenge
  },
  {
    method: "POST",
    route: { key: "passkeyGetToken" },
    handle: handlePasskeyGetToken
  },
  {
    method: "POST",
    route: { key: "passkeyEnrollmentChallenge" },
    handle: handlePasskeyEnrollmentChallenge
  },
  {
    method: "POST",
    route: { key: "passkeyEnrollmentVerify" },
    handle: handlePasskeyEnrollmentVerify
  },
  // The anonymous routes have no gate: each answers 404 itself when the feature is off, as on
  // nextjs, instead of falling through to the app.
  {
    method: "GET",
    route: { key: "anonymousSession" },
    handle: handleAnonymousSession
  },
  {
    method: "POST",
    route: { key: "anonymousSessionLogout" },
    handle: handleAnonymousSessionLogout
  },
  { route: { prefix: "/me/" }, handle: handleMyAccount },
  { route: { prefix: "/my-org/" }, handle: handleMyOrg }
];

/**
 * Entry point for every request through the middleware: an SDK route, or the session is rolled and
 * the request continues to the app.
 */
export async function dispatch(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  return (await matchRoute(req, setup)) ?? rollSession(req, setup);
}

/**
 * The response of the first route matching the request, or `undefined` when none does.
 */
async function matchRoute(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse | undefined> {
  const pathname = routePath(req);
  const { config } = setup;

  const entry = ROUTES.find(
    ({ method, route, enabled }) =>
      (!method || method === req.method) &&
      matchesPath(route, pathname, config.routes) &&
      (!enabled || enabled(config))
  );
  if (!entry) {
    return undefined;
  }

  if (
    "key" in entry.route &&
    entry.route.key === "login" &&
    isNonNavigationalRequest(req)
  ) {
    // A prefetch: 204 "intentionally did nothing", as on nextjs. `no-store`, because a 204 is
    // heuristically cacheable (RFC 9111) and a cached one would break real logins.
    return new NextResponse(null, {
      status: 204,
      headers: { "Cache-Control": "no-store" }
    });
  }
  return entry.handle(req, setup);
}

/**
 * The path compared with the routes: Next.js keeps the base path in `pathname` in middleware, so it
 * is cut off, then the trailing slash.
 */
function routePath(req: NextRequest): string {
  let { pathname } = req.nextUrl;
  const { basePath } = req.nextUrl;
  if (basePath && pathname.startsWith(basePath)) {
    pathname = pathname.slice(basePath.length) || "/";
  }
  return removeTrailingSlash(pathname);
}

function matchesPath(
  route: RouteEntry["route"],
  pathname: string,
  routes: Routes
): boolean {
  if ("prefix" in route) {
    return pathname.startsWith(route.prefix);
  }
  return pathname === routes[route.key];
}
