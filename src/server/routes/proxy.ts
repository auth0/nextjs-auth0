import { NextRequest, NextResponse } from "next/server.js";
import type { DPoPHandle } from "oauth4webapi";

import {
  DiscoveryError,
  MfaRequiredError,
  SdkError
} from "../../errors/index.js";
import type { ProxyOptions } from "../../types/index.js";
import { transferCookies } from "../../utils/anonymous-session-constants.js";
import { createSizeLimitedFetch } from "../../utils/fetchUtils.js";
import {
  buildForwardedRequestHeaders,
  buildForwardedResponseHeaders,
  transformTargetUrl
} from "../../utils/proxy.js";
import { middlewareContext, type CookieContext } from "../engine/context.js";
import {
  MAX_RESPONSE_BODY_SIZE,
  type EngineSetup
} from "../engine/create-engine.js";
import {
  createDpopHandle,
  fetcherFactory,
  toTokenSet
} from "../fetcher/create-fetcher.js";
import type { AccessTokenFactory } from "../fetcher/fetcher.js";
import { addCacheControlHeadersForSession } from "../http/cache-control.js";
import { readSession } from "../session/read-session.js";
import {
  retrieveAccessToken,
  type AccessToken
} from "../token/get-access-token.js";

// DPoP handles per audience, kept across proxied requests so nonces carry over, as on nextjs.
const dpopHandles = new WeakMap<EngineSetup, Map<string, DPoPHandle>>();

/**
 * Route: any method on /me/*. Proxied to the My Account API (`https://<domain>/me/v1`).
 */
export async function handleMyAccount(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  return withScratch(req, setup, async (ctx, issuer) =>
    handleProxy(req, setup, ctx, {
      proxyPath: "/me",
      targetBaseUrl: `${issuer}me/v1`,
      audience: `${issuer}me/`,
      scope: req.headers.get("scope")
    })
  );
}

/**
 * Route: any method on /my-org/*. Proxied to the My Organization API (`https://<domain>/my-org`).
 */
export async function handleMyOrg(
  req: NextRequest,
  setup: EngineSetup
): Promise<NextResponse> {
  return withScratch(req, setup, async (ctx, issuer) =>
    handleProxy(req, setup, ctx, {
      proxyPath: "/my-org",
      targetBaseUrl: `${issuer}my-org`,
      audience: `${issuer}my-org/`,
      scope: req.headers.get("scope")
    })
  );
}

/**
 * Runs the proxy with the request's issuer, then puts the cookies the engine wrote (a refresh, a
 * session expired, MFA context) on whichever response it returns.
 */
async function withScratch(
  req: NextRequest,
  setup: EngineSetup,
  run: (ctx: CookieContext, issuer: string) => Promise<NextResponse>
): Promise<NextResponse> {
  const scratch = NextResponse.next();
  const ctx = middlewareContext(req, scratch);
  const issuer = `https://${await setup.currentDomain(ctx)}/`;
  const res = await run(ctx, issuer);
  transferCookies(scratch, res);
  return res;
}

/**
 * nextjs's `#handleProxy`, with the token from `retrieveAccessToken` (the engine refreshes and
 * saves the session before the API call):
 * 1. no session, or one for another domain: 401, text body
 * 2. a CORS preflight: forwarded without a token
 * 3. headers from the allow list, `host` set to the target, the body buffered for a DPoP nonce retry
 * 4. tokens cached for this request, so a nonce retry does not refresh twice
 * 5. success: the upstream status, headers and body; no-cache when the session was refreshed
 * 6. MFA required: 403 with the MFA body, no-cache; any other token error: 401, text body;
 *    anything else (a `beforeSessionSaved` error too): 500, text body
 *
 * A `DiscoveryError` leaves the middleware, as on nextjs.
 */
async function handleProxy(
  req: NextRequest,
  setup: EngineSetup,
  ctx: CookieContext,
  options: ProxyOptions
): Promise<NextResponse> {
  const { config } = setup;
  const { state, error: sessionError } = await readSession(setup, ctx);
  if (sessionError || !state) {
    return new NextResponse(
      sessionError?.message ?? "The user does not have an active session.",
      {
        status: 401
      }
    );
  }

  // nextjs's `this.fetch`: no `User-Agent` and no timeout, so the browser's allowed headers go
  // through unchanged.
  const proxyFetch = createSizeLimitedFetch(
    config.options.customFetch ?? fetch,
    MAX_RESPONSE_BODY_SIZE
  );

  // handle preflight requests
  if (
    req.method === "OPTIONS" &&
    req.headers.has("access-control-request-method")
  ) {
    return handlePreflight(req, options, proxyFetch);
  }

  const headers = buildForwardedRequestHeaders(req);
  const useDPoP = config.options.useDPoP ?? false;

  // Buffer the body (cloned first when DPoP is on) so a DPoP nonce retry can send it again.
  const clonedReq = useDPoP ? req.clone() : req;
  const targetUrl = transformTargetUrl(req, options);

  // Set Host header to upstream host
  headers.set("host", targetUrl.host);

  const bodyBuffer = clonedReq.body ? await clonedReq.arrayBuffer() : undefined;

  const tokensByRequest = new Map<string, AccessToken>();
  let refreshed = false;
  // Error returned by `retrieveAccessToken`, kept so token failures (user must re-authenticate)
  // can be told apart from other proxy failures.
  let tokenError: SdkError | undefined;

  const getAccessToken: AccessTokenFactory = async (authParams) => {
    const cacheKey = JSON.stringify([
      authParams.refresh ?? false,
      authParams.audience ?? null,
      authParams.scope ?? null
    ]);
    const cached = tokensByRequest.get(cacheKey);
    if (cached) {
      return toTokenSet(cached);
    }
    const result = await retrieveAccessToken(setup, ctx, {
      audience: authParams.audience,
      scope: authParams.scope
    });
    if (result.error) {
      tokenError = result.error;
      throw result.error;
    }
    refreshed ||= result.refreshed;
    tokensByRequest.set(cacheKey, result.accessToken);
    return toTokenSet(result.accessToken);
  };

  const fetcher = await fetcherFactory(setup, {
    useDPoP,
    fetch: proxyFetch,
    getAccessToken,
    dpopHandle: await proxyDpopHandle(setup, options.audience)
  });

  try {
    const response = await fetcher.fetchWithAuth(
      targetUrl.toString(),
      {
        method: clonedReq.method,
        headers,
        body: bodyBuffer
      },
      { scope: options.scope, audience: options.audience }
    );

    const res = new NextResponse(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: buildForwardedResponseHeaders(response)
    });

    if (refreshed) {
      addCacheControlHeadersForSession(res);
    }

    return res;
  } catch (e: any) {
    // On nextjs discovery runs before the call and its failure leaves the middleware.
    if (e instanceof DiscoveryError) {
      throw e;
    }

    // MFA required: the session was saved again by `retrieveAccessToken`.
    if (e instanceof MfaRequiredError) {
      const res = NextResponse.json(e.toJSON(), { status: 403 });
      addCacheControlHeadersForSession(res);
      return res;
    }

    // Return 401 for any error returned by `retrieveAccessToken` (e.g. missing, stale or revoked
    // refresh token), matching `/auth/access-token`.
    // On `session_expired` the engine deleted the stored session; the delete goes out with this
    // response.
    if (tokenError && e === tokenError) {
      return new NextResponse(e.message, { status: 401 });
    }

    // Generic error handling for other errors
    return new NextResponse(
      e.cause || e.message || "An error occurred while proxying the request.",
      {
        status: 500
      }
    );
  }
}

/**
 * nextjs's `#handlePreflight`: forwarded without a token or DPoP proof (RFC 7231 4.3.1, RFC 9449
 * 4.1), with the upstream status and allowed headers back; a failure gives 500.
 */
async function handlePreflight(
  req: NextRequest,
  options: ProxyOptions,
  proxyFetch: typeof fetch
): Promise<NextResponse> {
  const headers = buildForwardedRequestHeaders(req);
  const targetUrl = transformTargetUrl(req, options);

  // Set Host header to upstream host
  headers.set("host", targetUrl.host);

  try {
    // Forward preflight directly WITHOUT DPoP/auth headers
    const preflightResponse = await proxyFetch(targetUrl.toString(), {
      method: "OPTIONS",
      headers
    });

    // Forward CORS headers from upstream
    return new NextResponse(null, {
      status: preflightResponse.status,
      headers: buildForwardedResponseHeaders(preflightResponse)
    });
  } catch (error: any) {
    // If preflight fails, return 500
    return new NextResponse(
      error.cause || error.message || "Preflight request failed",
      { status: 500 }
    );
  }
}

/**
 * The DPoP handle for an audience, created on first use (nextjs's `proxyDpopHandles`).
 */
async function proxyDpopHandle(
  setup: EngineSetup,
  audience: string
): Promise<DPoPHandle | undefined> {
  let handles = dpopHandles.get(setup);
  if (!handles) {
    handles = new Map();
    dpopHandles.set(setup, handles);
  }
  const existing = handles.get(audience);
  if (existing) {
    return existing;
  }
  const handle = await createDpopHandle(setup.config);
  if (handle) {
    handles.set(audience, handle);
  }
  return handle;
}
