import {
  ServerClient,
  type CookieSerializeOptions,
  type AuthorizationParameters as EngineAuthorizationParameters,
  type DomainResolver as EngineDomainResolver
} from "@auth0/auth0-server-js";

import packageJson from "../../../package.json" with { type: "json" };
import {
  DomainResolutionError,
  InvalidConfigurationError
} from "../../errors/index.js";
import type { DomainResolver } from "../../types/mcd.js";
import {
  ANON_TRANSFER_TOKEN_PARAM,
  DEFAULT_ANONYMOUS_SESSION_COOKIE_NAME,
  RESERVED_SESSION_TOKEN_PARAM
} from "../../utils/anonymous-session-constants.js";
import { createSizeLimitedFetch } from "../../utils/fetchUtils.js";
import { normalizeDomain } from "../../utils/normalize.js";
import type { Auth0ClientOptions } from "../types/options.js";
import type { CookieContext } from "./adapters/context.js";
import { NextCookieHandler } from "./adapters/cookie-handler.js";
import {
  createErrorMapper,
  toSetupError,
  wrapFetch,
  type ErrorMapper
} from "./adapters/errors.js";
import {
  createSessionMapper,
  type SessionMapper
} from "./adapters/session-mapper.js";
import { resolveConfig, type EngineConfig } from "./resolve-config.js";
import { NextAnonymousStore } from "./stores/anonymous-store.js";
import { NextStatefulStateStore } from "./stores/stateful-state-store.js";
import { NextStatelessStateStore } from "./stores/stateless-state-store.js";
import { NextTransactionStore } from "./stores/transaction-store.js";

// Maximum response body size (1 MB), as on nextjs: guards against oversized discovery, JWKS or
// token responses.
export const MAX_RESPONSE_BODY_SIZE = 1024 * 1024;
// nextjs's default anonymous cookie lifetime (30 days).
const DEFAULT_ANONYMOUS_COOKIE_MAX_AGE = 2592000;
// Authorization parameters that are ignored wherever they come from, the configuration or a call.
// The login runs the authorization code flow with PKCE, so a `nonce` is never checked and another
// `response_type` returns no code; `state` and the anonymous session parameters are set by the
// engine, and a value from a caller cannot be trusted.
const UNSUPPORTED_AUTHORIZATION_PARAMS = [
  "nonce",
  "response_type",
  "state",
  ANON_TRANSFER_TOKEN_PARAM,
  RESERVED_SESSION_TOKEN_PARAM
];

export type Engine = ServerClient<CookieContext>;
type GetEngine = () => Promise<Engine>;
type CurrentDomain = (ctx?: CookieContext) => Promise<NormalizedDomain>;
type BuildEngine = (
  domain: string | EngineDomainResolver<CookieContext>
) => Engine;

/**
 * A domain normalized as nextjs normalizes it.
 */
export interface NormalizedDomain {
  /**
   * The host, lowercased, without port or path (nextjs's `domain`).
   */
  domain: string;
  /**
   * The issuer URL (nextjs's `issuer`). It keeps the path, and the `http` scheme and the port with
   * `allowInsecureRequests`. This is the value given to the engine.
   */
  issuer: string;
}

export interface EngineSetup {
  /**
   * The engine for a call. Built at construction, or on first use when no domain was set at
   * construction.
   */
  getEngine: GetEngine;
  /**
   * The domain for a call: the host and the issuer given to the engine. In resolver mode this
   * calls the user's resolver.
   */
  currentDomain: CurrentDomain;
  errors: ErrorMapper;
  /**
   * The fetch used for engine calls (timeout, size limit, user agent), also used for WebFinger.
   */
  fetch: typeof fetch;
  cookieHandler: NextCookieHandler;
  sessionStore: NextStatelessStateStore | NextStatefulStateStore;
  transactionStore: NextTransactionStore;
  sessionMapper: SessionMapper;
  config: EngineConfig;
}

/**
 * Builds every engine piece and the engine `ServerClient` from today's `Auth0ClientOptions`.
 */
export function createEngine(options: Auth0ClientOptions): EngineSetup {
  const config = resolveConfig(options);
  const errors = createErrorMapper({
    secret: config.secret,
    mfaTokenTtl: config.mfaTokenTtl
  });
  const sessionMapper = createSessionMapper({
    audience: config.authorizationParameters.audience ?? undefined
  });
  const { cookieHandler, sessionStore, transactionStore } = createStores(
    config,
    sessionMapper
  );
  const anonymous = createAnonymousStore(config, cookieHandler);
  const customFetch = createFetch(options);
  // As on nextjs: on by default in tests, so a static `http` domain (a mock server) is kept.
  const allowInsecureRequests =
    options.allowInsecureRequests ?? process.env.NODE_ENV === "test";

  const build: BuildEngine = (domain) => {
    try {
      return new ServerClient<CookieContext>({
        domain,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        clientAssertionSigningKey: config.clientAssertionSigningKey,
        clientAssertionSigningAlg: config.clientAssertionSigningAlg,
        authorizationParams: {
          ...withoutUnsupportedParams(config.authorizationParameters),
          scope: config.loginScope
        } as EngineAuthorizationParameters,
        discoveryCache: options.discoveryCache,
        transactionIdentifier: config.transactionCookie.prefix,
        stateIdentifier: config.sessionCookie.name,
        enableParallelTransactions: config.enableParallelTransactions,
        customFetch,
        httpTimeout: options.httpTimeout ?? undefined,
        // `http` for a static domain only; a resolver's issuer always uses https.
        allowInsecureRequests,
        // nextjs always kept the path of the domain (an Okta custom authorization server, for
        // example). The engine then keeps it in the session's domain too.
        keepDomainPath: true,
        transactionStore,
        stateStore: sessionStore,
        ...anonymous,
        useMtls: config.useMtls,
        tokenRefreshBuffer: config.tokenRefreshBuffer,
        telemetry:
          options.enableTelemetry === false
            ? { enabled: false }
            : { name: "nextjs-auth0", version: packageJson.version },
        enterpriseConnect: options.enterpriseConnect
      });
    } catch (e) {
      throw toSetupError(e);
    }
  };

  return {
    ...selectEngine(config, allowInsecureRequests, build),
    errors,
    fetch: customFetch,
    cookieHandler,
    sessionStore,
    transactionStore,
    sessionMapper,
    config
  };
}

/**
 * The authorization parameters without the ones that are ignored.
 */
export function withoutUnsupportedParams(params: Record<string, unknown>) {
  return Object.fromEntries(
    Object.entries(params).filter(
      ([key]) => !UNSUPPORTED_AUTHORIZATION_PARAMS.includes(key)
    )
  );
}

/**
 * The cookie handler and the session and transaction stores, all sharing one handler.
 */
function createStores(config: EngineConfig, sessionMapper: SessionMapper) {
  const { sessionCookie, options } = config;
  const cookieHandler = new NextCookieHandler({
    sessionName: sessionCookie.name,
    domain: sessionCookie.domain,
    transient: sessionCookie.transient
  });

  const deleteOptions: CookieSerializeOptions = {
    httpOnly: true,
    sameSite: sessionCookie.sameSite,
    secure: sessionCookie.secure,
    path: sessionCookie.path,
    ...(sessionCookie.domain ? { domain: sessionCookie.domain } : {})
  };
  const storeOptions = {
    rolling: options.session?.rolling,
    absoluteDuration: options.session?.absoluteDuration,
    inactivityDuration: options.session?.inactivityDuration,
    cookie: {
      name: sessionCookie.name,
      sameSite: sessionCookie.sameSite,
      secure: sessionCookie.secure,
      path: sessionCookie.path
    },
    secret: config.secret,
    cookieHandler,
    sessionName: sessionCookie.name,
    deleteOptions
  };
  const sessionStore = options.sessionStore
    ? new NextStatefulStateStore({
        ...storeOptions,
        store: options.sessionStore,
        toStateData: sessionMapper.toStateData,
        toSessionData: sessionMapper.toSessionData
      })
    : new NextStatelessStateStore({
        ...storeOptions,
        fromLegacySession: sessionMapper.toStateData
      });

  const transactionStore = new NextTransactionStore({
    secret: config.secret,
    cookieHandler,
    cookieOptions: config.transactionCookie
  });

  return { cookieHandler, sessionStore, transactionStore };
}

/**
 * The engine's anonymous session options, only when `anonymousSession.enabled`. Without a store
 * the engine never mints a transfer ticket and never clears an anonymous session, as on nextjs
 * with the feature off.
 *
 * The store shares the session's cookie handler. That handler only adds `domain` and `transient`
 * to the session cookie's own names, so the anonymous cookie passes through unchanged (nextjs gave
 * it neither). The store writes its chunks as `auth0_anon__N`, nextjs's names, and clears them the
 * way nextjs did. nextjs's own anonymous cookies are not read (different encryption) and are
 * replaced on the first save or delete of the anonymous session.
 */
function createAnonymousStore(
  { anonymousSession, secret }: EngineConfig,
  cookieHandler: NextCookieHandler
) {
  if (!anonymousSession?.enabled) {
    return {};
  }
  const { cookie } = anonymousSession;
  const name = cookie?.name ?? DEFAULT_ANONYMOUS_SESSION_COOKIE_NAME;
  const cookieOptions = {
    sameSite: cookie?.sameSite ?? "lax",
    secure: cookie?.secure ?? true,
    path: "/"
  } as const;
  const anonymousStore = new NextAnonymousStore({
    secret,
    sessionTokenLifetime: cookie?.maxAge ?? DEFAULT_ANONYMOUS_COOKIE_MAX_AGE,
    cookie: cookieOptions,
    cookieHandler,
    name,
    deleteOptions: { httpOnly: true, ...cookieOptions }
  });
  return {
    anonymousStore,
    anonymousSessionIdentifier: name,
    clearAnonymousSessionOnLogin:
      anonymousSession.clearAnonymousSessionOnLogin ?? true
  };
}

interface EngineAccess {
  getEngine: GetEngine;
  currentDomain: CurrentDomain;
}

/**
 * Picks how the engine is built from the domain setup.
 */
function selectEngine(
  { domain }: EngineConfig,
  allowInsecureRequests: boolean,
  build: BuildEngine
): EngineAccess {
  if (typeof domain === "function") {
    return resolverEngine(domain, build);
  }
  if (domain) {
    return staticEngine(domain, allowInsecureRequests, build);
  }
  return lazyEngine(allowInsecureRequests, build);
}

/**
 * Static domain: one engine, built now.
 */
function staticEngine(
  domain: string,
  allowInsecureRequests: boolean,
  build: BuildEngine
): EngineAccess {
  const normalized = normalizeDomain(domain, { allowInsecureRequests });
  const engine = build(normalized.issuer);
  return {
    getEngine: async () => engine,
    currentDomain: async () => normalized
  };
}

/**
 * Resolver function: one engine, built now. The engine calls our wrapper on every request.
 */
function resolverEngine(
  resolver: DomainResolver,
  build: BuildEngine
): EngineAccess {
  const currentDomain: CurrentDomain = (ctx) => resolveDomain(resolver, ctx);
  const engine = build(async (ctx) => (await currentDomain(ctx)).issuer);
  return { getEngine: async () => engine, currentDomain };
}

/**
 * No domain at construction (env vars injected at runtime): built on first use from `AUTH0_DOMAIN`.
 * A failure is not kept, so the next call tries again.
 */
function lazyEngine(
  allowInsecureRequests: boolean,
  build: BuildEngine
): EngineAccess {
  let current: { engine: Engine; normalized: NormalizedDomain } | undefined;
  const load = () => {
    if (current) {
      return current;
    }
    const domain = process.env.AUTH0_DOMAIN;
    if (!domain) {
      throw new DomainResolutionError(
        "Domain resolver threw an error.",
        new InvalidConfigurationError(
          "Missing: domain: Set AUTH0_DOMAIN env var or pass domain in options."
        )
      );
    }
    const normalized = normalizeDomain(domain, { allowInsecureRequests });
    current = { engine: build(normalized.issuer), normalized };
    return current;
  };
  return {
    getEngine: async () => load().engine,
    currentDomain: async () => load().normalized
  };
}

/**
 * Calls the user's resolver with `{ headers, url }` and turns its failures into today's errors.
 * The value is normalized without `allowInsecureRequests`, as on nextjs: https, no port, the path
 * kept.
 */
async function resolveDomain(
  resolver: DomainResolver,
  ctx?: CookieContext
): Promise<NormalizedDomain> {
  let resolved: string;
  try {
    resolved = await resolver({
      headers: ctx?.headers ?? new Headers(),
      url: ctx?.url
    });
  } catch (err) {
    const cause = err instanceof Error ? err : new Error(String(err));
    throw new DomainResolutionError("Domain resolver threw an error.", cause);
  }
  if (!resolved) {
    throw new DomainResolutionError(
      "Domain resolver returned an empty string."
    );
  }
  const normalized = normalizeDomain(resolved);
  // nextjs normalizes the issuer again when it picks the client, which refuses a host that is not
  // valid (a space, `!`) with the same error.
  normalizeDomain(normalized.issuer);
  return normalized;
}

/**
 * The `fetch` given to the engine: `User-Agent` and 1 MB response limit, with network errors
 * recorded for the error mapper. The time limit is not set here: `httpTimeout` goes to the engine,
 * which applies it to every request it makes (and adds none when it is not set).
 */
function createFetch(options: Auth0ClientOptions): typeof fetch {
  const baseFetch = options.customFetch ?? fetch;
  const userAgent =
    options.enableTelemetry === false
      ? undefined
      : `nextjs-auth0/${packageJson.version}`;

  const withDefaults: typeof fetch = (input, init) => {
    const headers = new Headers(
      input instanceof Request ? input.headers : undefined
    );
    new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
    if (userAgent) {
      headers.set("User-Agent", userAgent);
    }
    return baseFetch(input, { ...init, headers });
  };

  return wrapFetch(
    createSizeLimitedFetch(withDefaults, MAX_RESPONSE_BODY_SIZE)
  );
}
