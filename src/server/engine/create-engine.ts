import {
  ServerClient,
  StatelessAnonymousStore,
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
import { DEFAULT_ANONYMOUS_SESSION_COOKIE_NAME } from "../../utils/anonymous-session-constants.js";
import { createSizeLimitedFetch } from "../../utils/fetchUtils.js";
import { normalizeDomain } from "../../utils/normalize.js";
import type { Auth0ClientOptions } from "../types/options.js";
import type { CookieContext } from "./context.js";
import { NextCookieHandler } from "./cookie-handler.js";
import {
  createErrorMapper,
  toSetupError,
  wrapFetch,
  type ErrorMapper
} from "./errors.js";
import { resolveConfig, type EngineConfig } from "./resolve-config.js";
import { createSessionMapper, type SessionMapper } from "./session-mapper.js";
import { NextStatefulStateStore } from "./stores/stateful-state-store.js";
import { NextStatelessStateStore } from "./stores/stateless-state-store.js";
import { NextTransactionStore } from "./stores/transaction-store.js";

// Maximum response body size (1 MB), as on `main`: guards against oversized discovery, JWKS or
// token responses.
export const MAX_RESPONSE_BODY_SIZE = 1024 * 1024;
// `main`'s default anonymous cookie lifetime (30 days).
const DEFAULT_ANONYMOUS_COOKIE_MAX_AGE = 2592000;

export type Engine = ServerClient<CookieContext>;
type GetEngine = () => Promise<Engine>;
type CurrentDomain = (ctx?: CookieContext) => Promise<string>;
type BuildEngine = (
  domain: string | EngineDomainResolver<CookieContext>
) => Engine;

export interface EngineSetup {
  /**
   * The engine for a call. Built at construction, or on first use when no domain was set at
   * construction.
   */
  getEngine: GetEngine;
  /**
   * The domain for a call, normalized as the engine gets it. In resolver mode this calls the
   * user's resolver.
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
  const anonymous = createAnonymousStore(config);
  const customFetch = createFetch(options);

  const build: BuildEngine = (domain) => {
    try {
      return new ServerClient<CookieContext>({
        domain,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        clientAssertionSigningKey: config.clientAssertionSigningKey,
        clientAssertionSigningAlg: config.clientAssertionSigningAlg,
        authorizationParams: {
          ...config.authorizationParameters,
          scope: config.loginScope
        } as EngineAuthorizationParameters,
        discoveryCache: options.discoveryCache,
        transactionIdentifier: config.transactionCookie.prefix,
        stateIdentifier: config.sessionCookie.name,
        enableParallelTransactions: config.enableParallelTransactions,
        customFetch,
        httpTimeout: options.httpTimeout ?? undefined,
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
    ...selectEngine(config, build),
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
 * the engine never mints a transfer ticket and never clears an anonymous session, as on `main`
 * with the feature off.
 *
 * The store has its own cookie handler for the anonymous name: it hides that name's look-alikes
 * (`main`'s `auth0_anon` / `auth0_anon__N`), and keeps the session's filter out of the way when
 * one name starts with the other.
 */
function createAnonymousStore({ anonymousSession, secret }: EngineConfig) {
  if (!anonymousSession?.enabled) {
    return {};
  }
  const { cookie } = anonymousSession;
  const name = cookie?.name ?? DEFAULT_ANONYMOUS_SESSION_COOKIE_NAME;
  const anonymousStore = new StatelessAnonymousStore<CookieContext>(
    {
      secret,
      sessionTokenLifetime: cookie?.maxAge ?? DEFAULT_ANONYMOUS_COOKIE_MAX_AGE,
      cookie: {
        sameSite: cookie?.sameSite ?? "lax",
        secure: cookie?.secure ?? true,
        path: "/"
      }
    },
    new NextCookieHandler({ sessionName: name })
  );
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
function selectEngine(config: EngineConfig, build: BuildEngine): EngineAccess {
  const { domain, options } = config;
  if (typeof domain === "function") {
    return resolverEngine(domain, build);
  }
  if (domain) {
    return staticEngine(domain, options.allowInsecureRequests, build);
  }
  return lazyEngine(options.allowInsecureRequests, build);
}

/**
 * Static domain: one engine, built now.
 */
function staticEngine(
  domain: string,
  allowInsecureRequests: boolean | undefined,
  build: BuildEngine
): EngineAccess {
  const host = staticDomain(domain, allowInsecureRequests);
  const engine = build(host);
  return { getEngine: async () => engine, currentDomain: async () => host };
}

/**
 * Resolver function: one engine, built now. The engine calls our wrapper on every request.
 */
function resolverEngine(
  resolver: DomainResolver,
  build: BuildEngine
): EngineAccess {
  const currentDomain: CurrentDomain = (ctx) => resolveDomain(resolver, ctx);
  const engine = build(currentDomain);
  return { getEngine: async () => engine, currentDomain };
}

/**
 * No domain at construction (env vars injected at runtime): built on first use from `AUTH0_DOMAIN`.
 * A failure is not kept, so the next call tries again.
 */
function lazyEngine(
  allowInsecureRequests: boolean | undefined,
  build: BuildEngine
): EngineAccess {
  let current: { engine: Engine; host: string } | undefined;
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
    const host = staticDomain(domain, allowInsecureRequests);
    current = { engine: build(host), host };
    return current;
  };
  return {
    getEngine: async () => load().engine,
    currentDomain: async () => load().host
  };
}

/**
 * Validates a static domain as `main` does and returns the host given to the engine.
 */
function staticDomain(domain: string, allowInsecureRequests?: boolean) {
  const normalized = normalizeDomain(domain, {
    allowInsecureRequests:
      allowInsecureRequests ?? process.env.NODE_ENV === "test"
  });
  assertEngineIssuer(domain, normalized);
  return normalized.domain;
}

/**
 * Calls the user's resolver with `{ headers, url }` and turns its failures into today's errors.
 */
async function resolveDomain(
  resolver: DomainResolver,
  ctx?: CookieContext
): Promise<string> {
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
  assertEngineIssuer(resolved, normalized);
  return normalized.domain;
}

/**
 * The engine always talks to `https://{host}/`. A domain whose issuer has another scheme, a port or
 * a path would silently reach the wrong server, so it is refused with a clear message instead.
 */
function assertEngineIssuer(
  input: string,
  { domain, issuer }: { domain: string; issuer: string }
) {
  if (issuer !== `https://${domain}/`) {
    throw new InvalidConfigurationError(
      `The domain "${input}" resolves to the issuer "${issuer}". Only https issuers at the root path are supported.`
    );
  }
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
