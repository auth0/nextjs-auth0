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
const MAX_RESPONSE_BODY_SIZE = 1024 * 1024;
const DEFAULT_HTTP_TIMEOUT = 5000;

export type Engine = ServerClient<CookieContext>;
type GetEngine = () => Promise<Engine>;
type BuildEngine = (
  domain: string | EngineDomainResolver<CookieContext>
) => Engine;

export interface EngineSetup {
  /**
   * The engine for a call. Built at construction, or on first use when no domain was set at
   * construction.
   */
  getEngine: GetEngine;
  errors: ErrorMapper;
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
        transactionStore,
        stateStore: sessionStore,
        useMtls: config.useMtls,
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
    getEngine: selectGetEngine(config, build),
    errors,
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
 * Picks how the engine is built from the domain setup.
 */
function selectGetEngine(config: EngineConfig, build: BuildEngine): GetEngine {
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
): GetEngine {
  const engine = build(staticDomain(domain, allowInsecureRequests));
  return async () => engine;
}

/**
 * Resolver function: one engine, built now. The engine calls our wrapper on every request.
 */
function resolverEngine(
  resolver: DomainResolver,
  build: BuildEngine
): GetEngine {
  const engine = build((ctx) => resolveDomain(resolver, ctx));
  return async () => engine;
}

/**
 * No domain at construction (env vars injected at runtime): built on first use from `AUTH0_DOMAIN`.
 * A failure is not kept, so the next call tries again.
 */
function lazyEngine(
  allowInsecureRequests: boolean | undefined,
  build: BuildEngine
): GetEngine {
  let engine: Engine | undefined;
  return async () => {
    if (engine) {
      return engine;
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
    engine = build(staticDomain(domain, allowInsecureRequests));
    return engine;
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
 * The `fetch` given to the engine: today's timeout, `User-Agent` and 1 MB response limit, with
 * network errors recorded for the error mapper.
 */
function createFetch(options: Auth0ClientOptions): typeof fetch {
  const baseFetch = options.customFetch ?? fetch;
  const httpTimeout = options.httpTimeout ?? DEFAULT_HTTP_TIMEOUT;
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
    const timeout = AbortSignal.timeout(httpTimeout);
    return baseFetch(input, {
      ...init,
      headers,
      signal: init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout
    });
  };

  return wrapFetch(
    createSizeLimitedFetch(withDefaults, MAX_RESPONSE_BODY_SIZE)
  );
}
