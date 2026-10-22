import {
  HTTP_TIMEOUT_MESSAGE,
  isValidHttpTimeout
} from "@auth0/auth0-server-js";

import {
  InvalidConfigurationError,
  MtlsError,
  MtlsErrorCode
} from "../../errors/index.js";
import type {
  AnonymousSessionConfig,
  AuthorizationParameters
} from "../../types/index.js";
import type { DomainResolver } from "../../types/mcd.js";
import {
  DEFAULT_MFA_CONTEXT_TTL_SECONDS,
  DEFAULT_SCOPES
} from "../../utils/constants.js";
import {
  ensureDefaultScope,
  getScopeForAudience
} from "../../utils/scope-helpers.js";
import { isUrl } from "../../utils/url-helpers.js";
import type { Auth0ClientOptions } from "../types/options.js";
import type { Routes } from "../types/routes.js";
import type { SessionCookieOptions } from "../types/session.js";
import type { TransactionCookieOptions } from "../types/transaction.js";

type LogoutStrategy = "auto" | "oidc" | "v2";
const VALID_LOGOUT_STRATEGIES: readonly LogoutStrategy[] = [
  "auto",
  "oidc",
  "v2"
];

/**
 * Options resolved once at construction, as nextjs does. Later steps read these instead of the raw
 * options, so env var fallbacks and defaults live in one place.
 */
export interface EngineConfig {
  options: Auth0ClientOptions;
  domain?: string | DomainResolver;
  clientId: string;
  clientSecret?: string;
  clientAssertionSigningKey?: string | CryptoKey;
  clientAssertionSigningAlg?: string;
  secret: string;
  appBaseUrl?: string | string[];
  /**
   * The caller's `authorizationParameters` with `scope` resolved (a string or a map per audience).
   */
  authorizationParameters: AuthorizationParameters;
  /**
   * The scope for the configured audience, as given to the engine.
   */
  loginScope: string;
  sessionCookie: Required<
    Pick<SessionCookieOptions, "name" | "secure" | "sameSite" | "path">
  > &
    Pick<SessionCookieOptions, "domain" | "transient">;
  transactionCookie: Required<Omit<TransactionCookieOptions, "domain">> &
    Pick<TransactionCookieOptions, "domain">;
  anonymousSession?: AnonymousSessionConfig;
  enableParallelTransactions: boolean;
  useMtls: boolean;
  mfaTokenTtl: number;
  tokenRefreshBuffer: number;
  signInReturnToPath: string;
  logoutStrategy: LogoutStrategy;
  routes: Routes;
  enableAccessTokenEndpoint: boolean;
  enableConnectAccountEndpoint: boolean;
}

/**
 * Reads options and env vars exactly as nextjs does (`client.ts`, `auth-client.ts` constructors),
 * in the same order, with the same warnings and errors.
 */
export function resolveConfig(options: Auth0ClientOptions): EngineConfig {
  const domain = options.domain ?? process.env.AUTH0_DOMAIN;
  const clientId = options.clientId ?? process.env.AUTH0_CLIENT_ID;
  const secret = options.secret ?? process.env.AUTH0_SECRET;
  const appBaseUrl = options.appBaseUrl ?? readEnvAppBaseUrl();
  const clientSecret = options.clientSecret ?? process.env.AUTH0_CLIENT_SECRET;
  const clientAssertionSigningKey =
    options.clientAssertionSigningKey ??
    process.env.AUTH0_CLIENT_ASSERTION_SIGNING_KEY;
  const useMtls = options.useMtls ?? process.env.AUTH0_MTLS === "true";

  warnMissingRequiredOptions(
    { domain, clientId, secret },
    !!(clientSecret || clientAssertionSigningKey) || useMtls
  );
  warnDpopWithoutKeyPair(options);
  const mfaTokenTtl = resolveMfaTokenTtl(
    options.mfaTokenTtl,
    process.env.AUTH0_MFA_TOKEN_TTL
  );
  assertTokenRefreshBuffer(options.tokenRefreshBuffer);
  assertHttpTimeout(options.httpTimeout);
  const cookies = resolveCookies(options);
  applySecureRules(cookies, appBaseUrl);
  warnInsecureRequestsInProduction(options);
  const { authorizationParameters, loginScope } = resolveScope(options);
  assertAppBaseUrls(appBaseUrl);
  const logoutStrategy = resolveLogoutStrategy(options.logoutStrategy);
  assertMtls(options, useMtls, clientSecret, clientAssertionSigningKey);

  return {
    options,
    domain,
    clientId: clientId as string,
    clientSecret,
    clientAssertionSigningKey,
    clientAssertionSigningAlg:
      options.clientAssertionSigningAlg ||
      process.env.AUTH0_CLIENT_ASSERTION_SIGNING_ALG,
    secret: secret as string,
    appBaseUrl,
    authorizationParameters,
    loginScope,
    sessionCookie: cookies.session,
    transactionCookie: cookies.transaction,
    anonymousSession: cookies.anonymousSession,
    enableParallelTransactions: options.enableParallelTransactions ?? true,
    useMtls,
    mfaTokenTtl,
    tokenRefreshBuffer: options.tokenRefreshBuffer ?? 0,
    signInReturnToPath: options.signInReturnToPath || "/",
    logoutStrategy,
    routes: resolveRoutes(options),
    enableAccessTokenEndpoint: options.enableAccessTokenEndpoint ?? true,
    enableConnectAccountEndpoint: options.enableConnectAccountEndpoint ?? false
  };
}

/**
 * `APP_BASE_URL` may hold several comma-separated URLs.
 */
function readEnvAppBaseUrl(): string | string[] | undefined {
  const value = process.env.APP_BASE_URL;
  if (!value?.includes(",")) {
    return value;
  }
  return value
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean);
}

function warnMissingRequiredOptions(
  required: Record<"domain" | "clientId" | "secret", unknown>,
  hasClientAuthentication: boolean
) {
  const missing = Object.entries(required)
    .filter(([, value]) => !value)
    .map(([key]) => key);
  if (!hasClientAuthentication) {
    missing.push("clientAuthentication");
  }
  if (!missing.length) {
    return;
  }

  const envVarNames: Record<string, string> = {
    domain: "AUTH0_DOMAIN",
    clientId: "AUTH0_CLIENT_ID",
    secret: "AUTH0_SECRET"
  };
  let errorMessage =
    "WARNING: Not all required options were provided when creating an instance of Auth0Client. Ensure to provide all missing options, either by passing it to the Auth0Client constructor, or by setting the corresponding environment variable.\n";
  missing.forEach((key) => {
    if (key === "clientAuthentication") {
      errorMessage += `Missing: clientAuthentication: Set either AUTH0_CLIENT_SECRET env var or AUTH0_CLIENT_ASSERTION_SIGNING_KEY env var, or pass clientSecret or clientAssertionSigningKey in options\n`;
    } else {
      errorMessage += `Missing: ${key}: Set ${envVarNames[key]} env var or pass ${key} in options\n`;
    }
  });
  console.error(errorMessage.trim());
}

/**
 * The key pair itself is loaded lazily on first use, as on nextjs, so the crypto code is only
 * bundled when DPoP is on.
 */
function warnDpopWithoutKeyPair(options: Auth0ClientOptions) {
  if (!options.useDPoP || options.dpopKeyPair) {
    return;
  }
  if (process.env.AUTH0_DPOP_PRIVATE_KEY && process.env.AUTH0_DPOP_PUBLIC_KEY) {
    return;
  }
  console.warn(
    "WARNING: useDPoP is set to true but dpopKeyPair is not provided. " +
      "DPoP will not be used and protected requests will use bearer authentication instead. " +
      "To enable DPoP, provide a dpopKeyPair in the Auth0Client options or set " +
      "AUTH0_DPOP_PUBLIC_KEY and AUTH0_DPOP_PRIVATE_KEY environment variables."
  );
}

/**
 * An invalid value warns and falls back to the default instead of throwing.
 */
function resolveMfaTokenTtl(
  optionValue: number | undefined,
  envValue: string | undefined
): number {
  if (optionValue !== undefined) {
    if (Number.isFinite(optionValue) && optionValue > 0) {
      return optionValue;
    }
    console.warn(
      `[auth0-nextjs] Invalid mfaTokenTtl option value: ${optionValue}. ` +
        `Using default: ${DEFAULT_MFA_CONTEXT_TTL_SECONDS} seconds.`
    );
    return DEFAULT_MFA_CONTEXT_TTL_SECONDS;
  }
  if (envValue !== undefined) {
    const parsed = parseInt(envValue, 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
    console.warn(
      `[auth0-nextjs] Invalid AUTH0_MFA_TOKEN_TTL environment variable: ${envValue}. ` +
        `Using default: ${DEFAULT_MFA_CONTEXT_TTL_SECONDS} seconds.`
    );
  }
  return DEFAULT_MFA_CONTEXT_TTL_SECONDS;
}

function assertTokenRefreshBuffer(value: unknown) {
  if (value == null) {
    return;
  }
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new TypeError(
      "tokenRefreshBuffer must be a non-negative number of seconds."
    );
  }
}

/**
 * The engine's rule and message for `httpTimeout` (an integer from 1 to 2147483647 milliseconds),
 * raised as our error. Checked here as well because the engine is built lazily when there is no
 * domain at construction, and the SDK's own requests (Fetcher, proxy, My Account) never reach the
 * engine's check. `null` from an untyped caller counts as not set, as `??` did on nextjs.
 */
function assertHttpTimeout(value: unknown) {
  if (value != null && !isValidHttpTimeout(value)) {
    throw new InvalidConfigurationError(HTTP_TIMEOUT_MESSAGE);
  }
}

interface ResolvedCookies {
  session: EngineConfig["sessionCookie"];
  transaction: EngineConfig["transactionCookie"];
  anonymousSession?: AnonymousSessionConfig;
  /**
   * `secure` as set by the caller, before the rules below force it on. `undefined` when not set.
   */
  explicitSecure: {
    session?: boolean;
    transaction?: boolean;
    anonymous?: boolean;
  };
}

/**
 * Session, transaction and anonymous cookie settings from options and env vars. `secure` is only
 * the caller's value here; `applySecureRules` decides the final value.
 */
function resolveCookies(options: Auth0ClientOptions): ResolvedCookies {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH;
  const sessionOptions = options.session?.cookie;
  const transactionOptions = options.transactionCookie;

  // Session cookie secure can be configured via options or AUTH0_COOKIE_SECURE.
  const envCookieSecure = process.env.AUTH0_COOKIE_SECURE;
  const sessionSecure =
    sessionOptions?.secure ??
    (envCookieSecure !== undefined ? envCookieSecure === "true" : undefined);
  // Transaction and anonymous session cookies only support secure via options (no env var).
  const transactionSecure = transactionOptions?.secure;
  const anonymousSecure = options.anonymousSession?.cookie?.secure;

  // A copy, so the caller's `anonymousSession` is never changed.
  const anonymousSession = options.anonymousSession?.cookie
    ? {
        ...options.anonymousSession,
        cookie: { ...options.anonymousSession.cookie }
      }
    : options.anonymousSession;

  return {
    session: {
      name: sessionOptions?.name ?? "__session",
      secure: sessionSecure ?? false,
      sameSite:
        sessionOptions?.sameSite ??
        (process.env.AUTH0_COOKIE_SAME_SITE as "lax" | "strict" | "none") ??
        "lax",
      path:
        sessionOptions?.path ??
        process.env.AUTH0_COOKIE_PATH ??
        basePath ??
        "/",
      transient:
        sessionOptions?.transient ??
        process.env.AUTH0_COOKIE_TRANSIENT === "true",
      domain: sessionOptions?.domain ?? process.env.AUTH0_COOKIE_DOMAIN
    },
    transaction: {
      prefix: transactionOptions?.prefix ?? "__txn_",
      secure: transactionSecure ?? false,
      sameSite: transactionOptions?.sameSite ?? "lax",
      path: transactionOptions?.path ?? basePath ?? "/",
      maxAge: transactionOptions?.maxAge ?? 3600,
      domain: transactionOptions?.domain ?? process.env.AUTH0_COOKIE_DOMAIN
    },
    anonymousSession,
    explicitSecure: {
      session: sessionSecure,
      transaction: transactionSecure,
      anonymous: anonymousSecure
    }
  };
}

/**
 * When cookies are forced to `secure`, as on nextjs:
 * - every `appBaseUrl` is https: forced on;
 * - no `appBaseUrl` in production (the request host is used at runtime): forced on, and a cookie
 *   explicitly marked insecure throws;
 * - no `appBaseUrl` in development with a cookie explicitly marked insecure: a warning.
 */
function applySecureRules(
  cookies: ResolvedCookies,
  appBaseUrl: string | string[] | undefined
) {
  const { explicitSecure } = cookies;

  if (appBaseUrl) {
    const urls = Array.isArray(appBaseUrl) ? appBaseUrl : [appBaseUrl];
    if (urls.every((url) => new URL(url).protocol === "https:")) {
      forceSecure(cookies);
    }
    return;
  }

  if (process.env.NODE_ENV === "production") {
    if (explicitSecure.session === false) {
      throw new InvalidConfigurationError(
        "Session cookies must be marked secure in production when appBaseUrl is not configured. Set AUTH0_COOKIE_SECURE=true or session.cookie.secure=true."
      );
    }
    if (explicitSecure.transaction === false) {
      throw new InvalidConfigurationError(
        "Transaction cookies must be marked secure in production when appBaseUrl is not configured. Set transactionCookie.secure=true."
      );
    }
    if (explicitSecure.anonymous === false) {
      throw new InvalidConfigurationError(
        "Anonymous session cookies must be marked secure in production when appBaseUrl is not configured. Set anonymousSession.cookie.secure=true."
      );
    }
    forceSecure(cookies);
    return;
  }

  const anyExplicitlyInsecure =
    explicitSecure.session === false ||
    explicitSecure.transaction === false ||
    explicitSecure.anonymous === false;
  if (process.env.NODE_ENV === "development" && anyExplicitlyInsecure) {
    console.warn(
      "'appBaseUrl' is not configured and cookies are explicitly marked insecure. This is allowed in development, but will throw in production. Configure appBaseUrl or set secure=true for session/transaction/anonymous-session cookies."
    );
  }
}

function forceSecure(cookies: ResolvedCookies) {
  cookies.session.secure = true;
  cookies.transaction.secure = true;
  if (cookies.anonymousSession?.cookie) {
    cookies.anonymousSession.cookie.secure = true;
  }
}

function warnInsecureRequestsInProduction(options: Auth0ClientOptions) {
  if (options.allowInsecureRequests && process.env.NODE_ENV === "production") {
    console.warn(
      "allowInsecureRequests is enabled in a production environment. This is not recommended."
    );
  }
}

/**
 * The resolved scope is written back into the caller's `authorizationParameters`, as on nextjs.
 * `loginScope` is the scope for the configured audience, which must include `openid`.
 */
function resolveScope(options: Auth0ClientOptions) {
  const authorizationParameters = options.authorizationParameters || {
    scope: DEFAULT_SCOPES
  };
  authorizationParameters.scope = ensureDefaultScope(authorizationParameters);

  const loginScope = getScopeForAudience(
    authorizationParameters.scope,
    authorizationParameters.audience
  );
  const scopes = loginScope?.split(" ").map((s) => s.trim());
  if (!loginScope || !scopes?.includes("openid")) {
    throw new Error(
      "The 'openid' scope must be included in the set of scopes. See https://auth0.com/docs"
    );
  }
  return { authorizationParameters, loginScope };
}

function assertAppBaseUrls(appBaseUrl: string | string[] | undefined) {
  if (!Array.isArray(appBaseUrl)) {
    return;
  }
  if (appBaseUrl.length === 0) {
    throw new InvalidConfigurationError(
      "APP_BASE_URL array configuration cannot be empty."
    );
  }
  const invalidUrls = appBaseUrl.filter((url) => isUrl(url) === false);
  if (invalidUrls.length > 0) {
    throw new InvalidConfigurationError(
      `APP_BASE_URL array contains invalid URLs: ${invalidUrls.join(", ")}`
    );
  }
}

/**
 * Defaults, then the `NEXT_PUBLIC_*_ROUTE` env vars, then `options.routes` spread last, as on nextjs
 * (an explicit `undefined` in `options.routes` overrides a default).
 */
function resolveRoutes(options: Auth0ClientOptions): Routes {
  const env = process.env;
  return {
    login: env.NEXT_PUBLIC_LOGIN_ROUTE || "/auth/login",
    logout: "/auth/logout",
    callback: "/auth/callback",
    backChannelLogout: "/auth/backchannel-logout",
    profile: env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile",
    accessToken: env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE || "/auth/access-token",
    federatedDomain:
      env.NEXT_PUBLIC_FEDERATED_DOMAIN_ROUTE || "/auth/federated-domain",
    connectAccount: "/auth/connect",
    mfaAuthenticators:
      env.NEXT_PUBLIC_MFA_AUTHENTICATORS_ROUTE || "/auth/mfa/authenticators",
    mfaChallenge: env.NEXT_PUBLIC_MFA_CHALLENGE_ROUTE || "/auth/mfa/challenge",
    mfaVerify: env.NEXT_PUBLIC_MFA_VERIFY_ROUTE || "/auth/mfa/verify",
    mfaAssociate: env.NEXT_PUBLIC_MFA_ASSOCIATE_ROUTE || "/auth/mfa/associate",
    passwordlessStart:
      env.NEXT_PUBLIC_PASSWORDLESS_START_ROUTE || "/auth/passwordless/start",
    passwordlessVerify:
      env.NEXT_PUBLIC_PASSWORDLESS_VERIFY_ROUTE || "/auth/passwordless/verify",
    passwordlessDbOtpChallenge:
      env.NEXT_PUBLIC_PASSWORDLESS_DB_OTP_CHALLENGE_ROUTE ||
      "/auth/passwordless/otp/challenge",
    passwordlessDbGetToken:
      env.NEXT_PUBLIC_PASSWORDLESS_DB_GET_TOKEN_ROUTE ||
      "/auth/passwordless/otp/token",
    passkeyRegister:
      env.NEXT_PUBLIC_PASSKEY_REGISTER_ROUTE || "/auth/passkey/register",
    passkeyChallenge:
      env.NEXT_PUBLIC_PASSKEY_CHALLENGE_ROUTE || "/auth/passkey/challenge",
    passkeyGetToken:
      env.NEXT_PUBLIC_PASSKEY_GET_TOKEN_ROUTE || "/auth/passkey/get-token",
    passkeyEnrollmentChallenge:
      env.NEXT_PUBLIC_PASSKEY_ENROLLMENT_CHALLENGE_ROUTE ||
      "/auth/passkey/enrollment-challenge",
    passkeyEnrollmentVerify:
      env.NEXT_PUBLIC_PASSKEY_ENROLLMENT_VERIFY_ROUTE ||
      "/auth/passkey/enrollment-verify",
    anonymousSession:
      env.NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE || "/auth/anonymous-session",
    anonymousSessionLogout:
      env.NEXT_PUBLIC_ANONYMOUS_SESSION_LOGOUT_ROUTE ||
      "/auth/anonymous-session/logout",
    ...options.routes
  };
}

/**
 * An invalid value logs an error and falls back to "auto" instead of throwing.
 */
function resolveLogoutStrategy(
  value: LogoutStrategy | undefined
): LogoutStrategy {
  const logoutStrategy = value || "auto";
  if (VALID_LOGOUT_STRATEGIES.includes(logoutStrategy)) {
    return logoutStrategy;
  }
  console.error(
    `Invalid logoutStrategy: ${logoutStrategy}. Must be one of: ${VALID_LOGOUT_STRATEGIES.join(", ")}. Defaulting to "auto"`
  );
  return "auto";
}

/**
 * Today's mTLS checks. The engine's own check never fires, because it always gets our `fetch`.
 */
function assertMtls(
  options: Auth0ClientOptions,
  useMtls: boolean,
  clientSecret: string | undefined,
  clientAssertionSigningKey: string | CryptoKey | undefined
) {
  if (!useMtls) {
    return;
  }
  if (options.useDPoP) {
    throw new MtlsError(
      MtlsErrorCode.MTLS_INCOMPATIBLE_CLIENT_AUTH,
      "useMtls and useDPoP cannot be used together. " +
        "When both are present, the server always issues a DPoP-bound token (cnf.jkt) " +
        "and the certificate is ignored for token binding."
    );
  }
  if (!options.customFetch) {
    throw new MtlsError(
      MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
      "useMtls requires the customFetch option (Auth0Client) or the fetch option (AuthClient) " +
        "to be set with a TLS-aware implementation (e.g. Node.js undici with a client certificate). " +
        "The standard fetch global has no client certificate API. " +
        "See https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#mtls for setup instructions."
    );
  }
  if (clientSecret || clientAssertionSigningKey) {
    throw new MtlsError(
      MtlsErrorCode.MTLS_INCOMPATIBLE_CLIENT_AUTH,
      "useMtls cannot be combined with clientSecret or clientAssertionSigningKey. " +
        "mTLS replaces secret-based client authentication entirely."
    );
  }
}
