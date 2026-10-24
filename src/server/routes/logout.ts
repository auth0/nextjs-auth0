import { NextRequest, NextResponse } from "next/server.js";
import type { LogoutOptions } from "@auth0/auth0-server-js";

import { DiscoveryError } from "../../errors/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import { resolveAppBaseUrl } from "../../utils/app-base-url.js";
import { middlewareContext } from "../engine/context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { addCacheControlHeadersForSession } from "../http/cache-control.js";
import { readSession } from "../session/read-session.js";

// The engine's error for `strategy: "oidc"` on a tenant without `end_session_endpoint`.
const RP_INITIATED_LOGOUT_NOT_SUPPORTED =
  "rp_initiated_logout_not_supported_error";

/**
 * Route: GET /auth/logout?returnTo=&state=&federated=. The engine revokes the refresh token,
 * deletes the session and builds the Auth0 logout URL; around it, nextjs's behavior:
 * - a session stored for another domain is not cleared and gives no hints
 * - the hint (`id_token_hint`, or `logout_hint` with `includeIdTokenHintInOIDCLogoutUrl: false`),
 *   `state` and `logoutStrategy` are passed to the engine
 * - transaction cookies are always deleted
 * - discovery failure, or `"oidc"` without RP-initiated logout: nextjs's 500 text
 */
export async function handleLogout(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  const { config } = setup;
  const scratch = NextResponse.next();
  const ctx = middlewareContext(req, scratch);

  const { state, error } = await readSession(setup, ctx);
  const domainMismatch = !!error;

  const { searchParams } = req.nextUrl;
  const returnTo =
    searchParams.get("returnTo") || resolveAppBaseUrl(config.appBaseUrl, req);
  const enterpriseConnect = !!config.options.enterpriseConnect;
  const federated =
    searchParams.get("federated") === "false"
      ? false
      : searchParams.has("federated") || enterpriseConnect;

  const options: LogoutOptions = {
    returnTo,
    federated,
    state: searchParams.get("state") ?? undefined,
    strategy: config.logoutStrategy
  };
  // A hint only from a session that counts (`state` is absent on a domain mismatch). The engine
  // sends one hint, taken from the session: the ID token, or the `sid` when told not to send it.
  if (state) {
    options.hint =
      config.options.includeIdTokenHintInOIDCLogoutUrl === false
        ? "logout_hint"
        : "id_token_hint";
  }

  let logoutUrl: URL;
  try {
    logoutUrl = await setup.errors.callEngine("logout", async () => {
      const engine = await setup.getEngine();
      if (enterpriseConnect) {
        // The engine clears nothing in this mode; the cookie written by `onCallback` is ours.
        if (!domainMismatch) {
          await setup.sessionStore.delete(config.sessionCookie.name, ctx);
        }
        return engine.logout(options, ctx);
      }
      if (domainMismatch && typeof config.domain !== "function") {
        // Static mode: the engine's `logout` has no domain check and would clear the session.
        return engine.authClient.buildLogoutUrl(options);
      }
      // Resolver mode: the engine also leaves another domain's session alone.
      return engine.logout(options, ctx);
    });
  } catch (e) {
    let message: string;
    if (e instanceof DiscoveryError) {
      message =
        "An error occurred while trying to initiate the logout request.";
    } else if (
      (e as { code?: unknown } | null)?.code ===
      RP_INITIATED_LOGOUT_NOT_SUPPORTED
    ) {
      message =
        "OIDC RP-Initiated Logout is not supported by the authorization server. Enable it or use a different logout strategy.";
    } else {
      throw e;
    }
    // The engine deleted the session before building the URL (unless another domain's).
    const res = new NextResponse(message, { status: 500 });
    setup.transactionStore.deleteAll(ctx);
    transferCookies(scratch, res);
    return res;
  }

  if (config.logoutStrategy === "auto" && logoutUrl.pathname === "/v2/logout") {
    console.warn(
      "The Auth0 client does not have RP-initiated logout enabled, the user will be redirected to the `/v2/logout` endpoint instead. Learn how to enable it here: https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0#enable-endpoint-discovery"
    );
  }

  const res = NextResponse.redirect(logoutUrl);
  setup.transactionStore.deleteAll(ctx);
  transferCookies(scratch, res);
  addCacheControlHeadersForSession(res);
  return res;
}
