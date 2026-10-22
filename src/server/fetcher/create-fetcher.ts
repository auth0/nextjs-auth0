import type { NextRequest } from "next/server.js";
import * as oauth from "oauth4webapi";

import packageJson from "../../../package.json" with { type: "json" };
import {
  AccessTokenError,
  AccessTokenErrorCode,
  DPoPError,
  DPoPErrorCode
} from "../../errors/index.js";
import type { DpopKeyPair, DpopOptions } from "../../types/dpop.js";
import type { TokenSet } from "../../types/index.js";
import { isRequest } from "../../utils/request.js";
import { getDpopConfig } from "../dpop/dpop-key-pair.js";
import { withCallContext } from "../engine/call-context.js";
import type { EngineSetup } from "../engine/create-engine.js";
import { withHttpTimeout } from "../engine/http-timeout.js";
import type { EngineConfig } from "../engine/resolve-config.js";
import { toNextRequest } from "../http/next-compat.js";
import { getSession } from "../session/get-session.js";
import {
  retrieveAccessToken,
  type AccessToken
} from "../token/get-access-token.js";
import type { PagesRouterRequest } from "../types/index.js";
import {
  AccessTokenFactory,
  CustomFetchImpl,
  Fetcher,
  type FetcherConfig,
  type FetcherHooks
} from "./fetcher.js";

export interface CreateFetcherOptions<TOutput extends Response> {
  useDPoP?: boolean;
  getAccessToken?: AccessTokenFactory;
  baseUrl?: string;
  fetch?: CustomFetchImpl<TOutput>;
}

interface FetcherFactoryOptions<
  TOutput extends Response
> extends CreateFetcherOptions<TOutput> {
  getAccessToken: AccessTokenFactory;
  dpopHandle?: oauth.DPoPHandle;
}

/**
 * `createFetcher(req, options)`, nextjs's code with the token from the engine:
 * 1. no session: `missing_session`, as on nextjs (a session for another domain throws its error)
 * 2. each `fetchWithAuth` gets its token with `retrieveAccessToken` (the engine refreshes and
 *    saves where cookies can be written; a Server Component skips the save with a dev warning)
 * 3. a `getAccessToken` passed in `options` is not used, as on nextjs
 */
export async function createFetcher<TOutput extends Response>(
  setup: EngineSetup,
  req: PagesRouterRequest | NextRequest | Request | undefined,
  options: CreateFetcherOptions<TOutput>
): Promise<Fetcher<TOutput>> {
  if (!(await getSession(setup, req))) {
    throw new AccessTokenError(
      AccessTokenErrorCode.MISSING_SESSION,
      "The user does not have an active session."
    );
  }

  const input = req && isRequest(req) ? toNextRequest(req) : req;
  const getAccessToken: AccessTokenFactory = (getAccessTokenOptions) =>
    withCallContext(input, undefined, async (ctx) => {
      const result = await retrieveAccessToken(
        setup,
        ctx,
        getAccessTokenOptions || {}
      );
      if (result.error) {
        throw result.error;
      }
      return toTokenSet(result.accessToken);
    });

  return fetcherFactory(setup, { ...options, getAccessToken });
}

/**
 * nextjs's `fetcherFactory`, without its discovery check (the fetcher does not use the metadata).
 * DPoP on with no key pair throws `dpop_configuration_error`.
 */
export async function fetcherFactory<TOutput extends Response>(
  { config }: EngineSetup,
  options: FetcherFactoryOptions<TOutput>
): Promise<Fetcher<TOutput>> {
  const { dpopKeyPair, dpopOptions } = await getDpopConfig(config);
  const useDPoP = config.options.useDPoP ?? false;
  if (useDPoP && !dpopKeyPair) {
    throw new DPoPError(
      DPoPErrorCode.DPOP_CONFIGURATION_ERROR,
      "DPoP is enabled but no keypair is configured."
    );
  }

  const shouldUseDpop = useDPoP && (options.useDPoP ?? true);

  const fetcherConfig: FetcherConfig<TOutput> = {
    // Fetcher-scoped DPoP handle and nonce management
    dpopHandle: shouldUseDpop
      ? (options.dpopHandle ?? newDpopHandle(config, dpopKeyPair!, dpopOptions))
      : undefined,
    httpOptions: () => httpOptions(config.options),
    allowInsecureRequests: config.options.allowInsecureRequests ?? false,
    retryConfig: dpopOptions?.retry,
    // The app's `httpTimeout` on each request, the DPoP nonce retry included. The Fetcher falls back to
    // the global fetch when none is given.
    fetch:
      config.options.httpTimeout == null
        ? options.fetch
        : withHttpTimeout(
            options.fetch ?? (fetch as unknown as CustomFetchImpl<TOutput>),
            config.options.httpTimeout
          ),
    getAccessToken: options.getAccessToken,
    baseUrl: options.baseUrl
  };

  const fetcherHooks: FetcherHooks = {
    getAccessToken: options.getAccessToken,
    isDpopEnabled: () => shouldUseDpop
  };

  return new Fetcher<TOutput>(fetcherConfig, fetcherHooks);
}

/**
 * A DPoP handle with nextjs's client metadata (`clockSkew` / `clockTolerance` from the resolved
 * DPoP options).
 */
export async function createDpopHandle(
  config: EngineConfig
): Promise<oauth.DPoPHandle | undefined> {
  const { dpopKeyPair, dpopOptions } = await getDpopConfig(config);
  return config.options.useDPoP && dpopKeyPair
    ? newDpopHandle(config, dpopKeyPair, dpopOptions)
    : undefined;
}

function newDpopHandle(
  config: EngineConfig,
  keyPair: DpopKeyPair,
  dpopOptions: DpopOptions | undefined
): oauth.DPoPHandle {
  const clientMetadata: oauth.Client = { client_id: config.clientId };
  if (typeof dpopOptions?.clockSkew === "number") {
    clientMetadata[oauth.clockSkew] = dpopOptions.clockSkew;
  }
  if (typeof dpopOptions?.clockTolerance === "number") {
    clientMetadata[oauth.clockTolerance] = dpopOptions.clockTolerance;
  }
  if (config.useMtls) {
    clientMetadata.use_mtls_endpoint_aliases = true;
  }
  return oauth.DPoP(clientMetadata, keyPair);
}

/**
 * nextjs's `httpOptions` headers (oauth4webapi uses only the signal for resource requests, so they
 * are kept for parity). The time limit is not here: it is on the fetch, see `fetcherFactory`.
 */
function httpOptions(options: EngineConfig["options"]) {
  const headers = new Headers();
  if (options.enableTelemetry ?? true) {
    const name = "nextjs-auth0";
    const version = packageJson.version;
    headers.set("User-Agent", `${name}/${version}`);
    headers.set("Auth0-Client", btoa(JSON.stringify({ name, version })));
  }
  return { headers };
}

/**
 * The fields the fetcher reads (`accessToken`, `token_type`), in nextjs's `TokenSet` shape.
 */
export function toTokenSet(accessToken: AccessToken): TokenSet {
  return {
    accessToken: accessToken.token,
    expiresAt: accessToken.expiresAt,
    scope: accessToken.scope,
    token_type: accessToken.token_type,
    audience: accessToken.audience
  };
}
