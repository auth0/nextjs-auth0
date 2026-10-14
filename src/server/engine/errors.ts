import { mapAnonymousErrorCode } from "../../errors/anonymous-session-errors.js";
import {
  AccessTokenError,
  AccessTokenErrorCode,
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode,
  AuthorizationCodeGrantError,
  AuthorizationCodeGrantRequestError,
  AuthorizationError,
  BackchannelAuthenticationError,
  BackchannelLogoutError,
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode,
  DiscoveryError,
  EnterpriseConnectError,
  InvalidConfigurationError,
  InvalidStateError,
  MfaChallengeError,
  MfaEnrollmentError,
  MfaGetAuthenticatorsError,
  MfaRequiredError,
  MfaVerifyError,
  MtlsError,
  MtlsErrorCode,
  OAuth2Error,
  PasskeyChallengeError,
  PasskeyGetTokenError,
  PasskeyRegisterError,
  PasswordlessDbChallengeError,
  PasswordlessDbGetTokenError,
  PasswordlessStartError,
  PasswordlessVerifyError,
  SdkError,
  TokenRevocationError,
  TokenRevocationErrorCode,
  type MfaRequirements
} from "../../errors/index.js";
import { DEFAULT_MFA_CONTEXT_TTL_SECONDS } from "../../utils/constants.js";
import { encryptMfaToken } from "../../utils/mfa-utils.js";
import { mapSttServerError } from "../../utils/session-transfer-helpers.js";

/**
 * The engine call an error came from. The same engine error means different things in
 * different calls, so the mapping is chosen per operation.
 */
export type EngineOperation =
  | "setup"
  | "login"
  | "callback"
  | "refresh"
  | "connectionToken"
  | "revoke"
  | "customTokenExchange"
  | "sessionTransfer"
  | "backchannelAuthentication"
  | "backchannelLogout"
  | "mfaGetAuthenticators"
  | "mfaEnroll"
  | "mfaChallenge"
  | "mfaVerify"
  | "passkeyRegister"
  | "passkeyChallenge"
  | "passkeyGetToken"
  | "passwordlessStart"
  | "passwordlessVerify"
  | "passwordlessDbChallenge"
  | "passwordlessDbGetToken"
  | "anonymous";

export interface EngineErrorContext {
  /**
   * Audience and scope of the call, encrypted into the `mfa_token` of an `MfaRequiredError`.
   */
  audience?: string;
  scope?: string;
  /**
   * The callback URL (`callback` only), to tell an Auth0 `?error=` from a failed token request.
   */
  callbackUrl?: URL;
  /**
   * Whether the session holds an access token for the audience (`refresh` only). The engine
   * reports a missing refresh token the same way in both cases; today's message differs.
   */
  accessTokenFound?: boolean;
}

export interface ErrorMapperOptions {
  /**
   * `AUTH0_SECRET`, used to encrypt the `mfa_token`.
   */
  secret: string;
  /**
   * `mfaTokenTtl` in seconds, as today.
   */
  mfaTokenTtl: number;
}

export interface ErrorMapper {
  /**
   * Runs an engine call; on failure, throws today's error for it (sync throws included).
   */
  callEngine<T>(
    operation: EngineOperation,
    fn: () => T | Promise<T>,
    ctx?: EngineErrorContext
  ): Promise<T>;
  /**
   * Today's error for an engine error. Errors it does not recognize are returned unchanged.
   */
  toSdkError(
    error: unknown,
    operation: EngineOperation,
    ctx?: EngineErrorContext
  ): Promise<unknown>;
}

// Shape of an engine error (`ApiError` in auth0-auth-js). Read by `code`, never `instanceof`:
// the engine ships CJS and ESM builds, so its classes can exist twice.
interface EngineError {
  code?: unknown;
  message?: string;
  statusCode?: number;
  cause?: {
    error?: string;
    error_description?: string;
    message?: string;
    mfa_token?: string;
    mfa_requirements?: MfaRequirements;
  };
}

// Errors thrown by `fetch` itself (network down, unknown host), recorded by `wrapFetch`. A
// `TypeError` from anywhere else (a store, a resolver) must not be taken for one.
const fetchErrors = new WeakSet<object>();

/**
 * Wraps the `fetch` given to the engine so the mapper can recognize network failures by identity.
 * The error is rethrown unchanged.
 */
export function wrapFetch(fetchFn: typeof fetch): typeof fetch {
  return async (input, init) => {
    try {
      return await fetchFn(input, init);
    } catch (e) {
      if (typeof e === "object" && e !== null) fetchErrors.add(e);
      throw e;
    }
  };
}

function codeOf(e: unknown): string | undefined {
  const code = (e as EngineError | null)?.code;
  return typeof code === "string" ? code : undefined;
}

function causeOf(e: unknown): EngineError["cause"] {
  const cause = (e as EngineError | null)?.cause;
  return typeof cause === "object" && cause !== null ? cause : undefined;
}

/**
 * A failure to fetch the OpenID configuration. Inside the engine every token endpoint call is
 * wrapped in an engine class, so an openid-client error (`OAUTH_*`) or a fetch error that reaches
 * us can only come from discovery.
 */
function isDiscoveryShaped(e: unknown): boolean {
  if (typeof e !== "object" || e === null) return false;
  return codeOf(e)?.startsWith("OAUTH_") === true || fetchErrors.has(e);
}

function isEngineMfaRequired(e: unknown): boolean {
  return causeOf(e)?.error === "mfa_required";
}

// The engine fills a missing `error` / `error_description` with `""`, so `||`, not `??`.
function oauth2ErrorFrom(e: unknown, fallbackCode = "unknown_error") {
  const cause = causeOf(e);
  return new OAuth2Error({
    code: cause?.error || fallbackCode,
    message: cause?.error_description || undefined
  });
}

// `{ error, error_description }` cause of the MFA, passkey and passwordless classes, set only
// when Auth0 returned an `error`, as today.
function apiErrorBodyFrom(e: unknown) {
  const cause = causeOf(e);
  return cause?.error
    ? { error: cause.error, error_description: cause.error_description ?? "" }
    : undefined;
}

type FeatureErrorClass = new (
  error: string,
  error_description: string,
  cause?: { error: string; error_description: string }
) => SdkError;

interface FeatureMapping {
  ErrorClass: FeatureErrorClass;
  engineCode: string;
  // Description when Auth0 gave none.
  defaultDescription: string;
  // Calls to the token endpoint: discovery and MFA step-up apply. Other calls are plain HTTP
  // requests, where any other failure is `unexpected_error`, as today.
  tokenEndpoint?: boolean;
  unexpectedDescription?: string;
}

const featureMappings: Partial<Record<EngineOperation, FeatureMapping>> = {
  mfaGetAuthenticators: {
    ErrorClass: MfaGetAuthenticatorsError,
    engineCode: "mfa_list_authenticators_error",
    defaultDescription: "Failed to retrieve authenticators",
    unexpectedDescription: "Unexpected error during authenticator retrieval"
  },
  mfaEnroll: {
    ErrorClass: MfaEnrollmentError,
    engineCode: "mfa_enrollment_error",
    defaultDescription: "Failed to enroll authenticator",
    unexpectedDescription: "Unexpected error during MFA enrollment"
  },
  mfaChallenge: {
    ErrorClass: MfaChallengeError,
    engineCode: "mfa_challenge_error",
    defaultDescription: "Failed to initiate MFA challenge",
    unexpectedDescription: "Unexpected error during MFA challenge"
  },
  mfaVerify: {
    ErrorClass: MfaVerifyError,
    engineCode: "mfa_verify_error",
    defaultDescription: "MFA verification failed",
    tokenEndpoint: true
  },
  passkeyRegister: {
    ErrorClass: PasskeyRegisterError,
    engineCode: "passkey_register_error",
    defaultDescription: "Failed to get passkey signup challenge",
    unexpectedDescription: "Unexpected error during passkey signup challenge"
  },
  passkeyChallenge: {
    ErrorClass: PasskeyChallengeError,
    engineCode: "passkey_challenge_error",
    defaultDescription: "Failed to get passkey login challenge",
    unexpectedDescription: "Unexpected error during passkey login challenge"
  },
  passkeyGetToken: {
    ErrorClass: PasskeyGetTokenError,
    engineCode: "passkey_get_token_error",
    defaultDescription: "Passkey verification failed",
    tokenEndpoint: true
  },
  passwordlessStart: {
    ErrorClass: PasswordlessStartError,
    engineCode: "passwordless_start_error",
    defaultDescription: "Failed to start passwordless flow",
    unexpectedDescription: "Unexpected error during passwordless start"
  },
  passwordlessVerify: {
    ErrorClass: PasswordlessVerifyError,
    engineCode: "passwordless_verify_error",
    defaultDescription: "Passwordless verification failed",
    tokenEndpoint: true
  },
  passwordlessDbChallenge: {
    ErrorClass: PasswordlessDbChallengeError,
    engineCode: "passwordless_challenge_error",
    defaultDescription: "Failed to request OTP challenge",
    unexpectedDescription: "Unexpected error during OTP challenge"
  },
  passwordlessDbGetToken: {
    ErrorClass: PasswordlessDbGetTokenError,
    engineCode: "passwordless_db_get_token_error",
    defaultDescription: "Passwordless DB token exchange failed",
    tokenEndpoint: true
  }
};

const ACCESS_TOKEN_MISSING_SESSION =
  "The user does not have an active session.";

/**
 * Turns engine errors into today's error classes, codes and messages (`main`'s text), so
 * `error.code` checks and `instanceof` checks on our classes keep working.
 *
 * - Engine errors are matched on `code`, and Auth0's error is read from `cause`.
 * - Our own errors (`SdkError`) and anything not recognized are returned unchanged.
 */
export function createErrorMapper({
  secret,
  mfaTokenTtl
}: ErrorMapperOptions): ErrorMapper {
  async function mfaRequiredFrom(
    e: unknown,
    ctx: EngineErrorContext | undefined,
    { chained = false }: { chained?: boolean } = {}
  ): Promise<MfaRequiredError> {
    const cause = causeOf(e);
    const mfaToken = cause?.mfa_token;
    const encryptedToken = mfaToken
      ? await encryptMfaToken(
          mfaToken,
          ctx?.audience ?? "",
          ctx?.scope ?? "",
          cause?.mfa_requirements,
          secret,
          chained ? DEFAULT_MFA_CONTEXT_TTL_SECONDS : mfaTokenTtl
        )
      : // No token to continue with: the user has to log in again.
        "";
    const description =
      cause?.error_description ||
      (chained
        ? "Additional MFA factor required"
        : mfaToken
          ? "Multi-factor authentication is required."
          : "Multi-factor authentication is required. Please log in again.");
    return new MfaRequiredError(
      description,
      encryptedToken,
      cause?.mfa_requirements,
      oauth2ErrorFrom(e, "mfa_required")
    );
  }

  // Rows that apply to every operation.
  function fromAnyOperation(e: unknown, code: string | undefined) {
    switch (code) {
      case "invalid_configuration_error":
      case "missing_required_argument_error":
      case "missing_client_auth_error":
        return new InvalidConfigurationError((e as EngineError).message);
      case "mtls_without_custom_fetch_not_supported":
        return new MtlsError(
          MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH,
          "useMtls requires the customFetch option (Auth0Client) or the fetch option (AuthClient) " +
            "to be set with a TLS-aware implementation (e.g. Node.js undici with a client certificate). " +
            "The standard fetch global has no client certificate API. " +
            "See https://github.com/auth0/nextjs-auth0/blob/main/EXAMPLES.md#mtls for setup instructions."
        );
      case "enterprise_connect_not_supported":
        return new EnterpriseConnectError();
      default:
        return undefined;
    }
  }

  async function fromFeature(
    e: unknown,
    code: string | undefined,
    mapping: FeatureMapping,
    ctx: EngineErrorContext | undefined,
    chainedMfa: boolean
  ): Promise<unknown> {
    const { ErrorClass } = mapping;
    if (code === mapping.engineCode) {
      // Step-up only when Auth0 gave an `mfa_token`, except on MFA verify (chained MFA).
      if (
        mapping.tokenEndpoint &&
        isEngineMfaRequired(e) &&
        (chainedMfa || causeOf(e)?.mfa_token)
      ) {
        return mfaRequiredFrom(e, ctx, { chained: chainedMfa });
      }
      const cause = causeOf(e);
      return new ErrorClass(
        cause?.error || "unknown_error",
        cause?.error_description ||
          (mapping.tokenEndpoint ? cause?.message : undefined) ||
          mapping.defaultDescription,
        apiErrorBodyFrom(e)
      );
    }
    if (mapping.tokenEndpoint) {
      return isDiscoveryShaped(e)
        ? new ErrorClass(
            "discovery_error",
            "Failed to discover authorization server metadata"
          )
        : e;
    }
    // Plain HTTP calls: any other failure (network, a body that is not JSON).
    return new ErrorClass("unexpected_error", mapping.unexpectedDescription!);
  }

  async function toSdkError(
    e: unknown,
    operation: EngineOperation,
    ctx?: EngineErrorContext
  ): Promise<unknown> {
    if (typeof e !== "object" || e === null || e instanceof SdkError) return e;

    const code = codeOf(e);
    // An empty token passed to revoke: today's `revokeToken("")` result.
    if (operation === "revoke" && code === "missing_required_argument_error") {
      return new TokenRevocationError(
        TokenRevocationErrorCode.MISSING_REFRESH_TOKEN,
        "A token is required to perform revocation."
      );
    }
    const anyMapped = fromAnyOperation(e, code);
    if (anyMapped) return anyMapped;

    const feature = featureMappings[operation];
    if (feature) {
      return fromFeature(e, code, feature, ctx, operation === "mfaVerify");
    }

    switch (operation) {
      case "refresh":
        if (code === "token_by_refresh_token_error") {
          if (!causeOf(e)) {
            // Thrown before any request: no refresh token.
            return new AccessTokenError(
              AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
              ctx?.accessTokenFound === false
                ? "No access token found and a refresh token was not provided. The user needs to re-authenticate."
                : "The access token has expired and a refresh token was not provided. The user needs to re-authenticate."
            );
          }
          if (isEngineMfaRequired(e)) return mfaRequiredFrom(e, ctx);
          return new AccessTokenError(
            AccessTokenErrorCode.FAILED_TO_REFRESH_TOKEN,
            "The access token has expired and there was an error while trying to refresh it.",
            oauth2ErrorFrom(e)
          );
        }
        if (code === "session_expired") {
          return new AccessTokenError(
            AccessTokenErrorCode.SESSION_EXPIRED,
            "The session has expired and the user must re-authenticate."
          );
        }
        if (code === "missing_session_error") {
          return new AccessTokenError(
            AccessTokenErrorCode.MISSING_SESSION,
            ACCESS_TOKEN_MISSING_SESSION
          );
        }
        break;

      case "callback": {
        if (code === "missing_transaction_error")
          return new InvalidStateError();
        if (code === "token_by_code_error") {
          const authError = ctx?.callbackUrl?.searchParams.get("error");
          if (authError) {
            return new AuthorizationError({
              cause: new OAuth2Error({
                code: authError,
                message:
                  ctx?.callbackUrl?.searchParams.get("error_description") ??
                  undefined
              })
            });
          }
          // No `statusCode`: no response came back (network failure, timeout, or the request
          // could not be built). The engine sets it from the response it received.
          if ((e as EngineError).statusCode === undefined) {
            return new AuthorizationCodeGrantRequestError(
              causeOf(e)?.message || (e as EngineError).message
            );
          }
          return new AuthorizationCodeGrantError({ cause: oauth2ErrorFrom(e) });
        }
        if (code === "organization_validation_error") {
          // The ID token's organization is missing or different (the engine checks it).
          return new AuthorizationCodeGrantError({
            cause: new OAuth2Error({
              code: "organization_validation_error",
              message: (e as EngineError).message
            })
          });
        }
        if (code === "session_expired") {
          return new AccessTokenError(
            AccessTokenErrorCode.SESSION_EXPIRED,
            "The session has expired and the user must re-authenticate."
          );
        }
        break;
      }

      case "connectionToken":
        if (code === "token_for_connection_error") {
          if (!causeOf(e)) {
            return new AccessTokenForConnectionError(
              AccessTokenForConnectionErrorCode.MISSING_REFRESH_TOKEN,
              "A refresh token was not present, Connection Access Token requires a refresh token. The user needs to re-authenticate."
            );
          }
          return new AccessTokenForConnectionError(
            AccessTokenForConnectionErrorCode.FAILED_TO_EXCHANGE,
            "There was an error trying to exchange the refresh token for a connection access token.",
            oauth2ErrorFrom(e)
          );
        }
        if (code === "missing_session_error") {
          return new AccessTokenForConnectionError(
            AccessTokenForConnectionErrorCode.MISSING_SESSION,
            ACCESS_TOKEN_MISSING_SESSION
          );
        }
        break;

      case "revoke":
        if (code === "token_revocation_error") {
          return new TokenRevocationError(
            TokenRevocationErrorCode.FAILED_TO_REVOKE,
            "An error occurred while trying to revoke the token.",
            new OAuth2Error({
              code: causeOf(e)?.error || "revoke_failed",
              message: causeOf(e)?.message || (e as EngineError).message
            })
          );
        }
        // The engine throws this when it finds no refresh token, with or without a session. The
        // caller checks for a session first (3.4.3), so here the session has no refresh token.
        if (code === "missing_session_error") {
          return new TokenRevocationError(
            TokenRevocationErrorCode.MISSING_REFRESH_TOKEN,
            "The session does not contain a refresh token to revoke."
          );
        }
        break;

      case "customTokenExchange":
        if (code === "token_exchange_error") {
          return new CustomTokenExchangeError(
            CustomTokenExchangeErrorCode.EXCHANGE_FAILED,
            "There was an error trying to exchange the token.",
            new OAuth2Error({
              code: causeOf(e)?.error || "unknown_error",
              message:
                causeOf(e)?.error_description ||
                causeOf(e)?.message ||
                (e as EngineError).message
            })
          );
        }
        if (isDiscoveryShaped(e)) {
          return new CustomTokenExchangeError(
            CustomTokenExchangeErrorCode.EXCHANGE_FAILED,
            "Failed to discover authorization server metadata.",
            new OAuth2Error({
              code: "discovery_error",
              message: (e as EngineError).message
            })
          );
        }
        return e;

      case "sessionTransfer":
        if (code === "actor_unavailable") {
          return new CustomTokenExchangeError(
            CustomTokenExchangeErrorCode.ACTOR_UNAVAILABLE,
            (e as EngineError).message ?? ""
          );
        }
        if (code === "token_exchange_error") {
          const errorCode = causeOf(e)?.error || "unknown_error";
          const description = causeOf(e)?.error_description || undefined;
          return new CustomTokenExchangeError(
            mapSttServerError(errorCode) ??
              CustomTokenExchangeErrorCode.EXCHANGE_FAILED,
            description ??
              "There was an error trying to exchange the token for a Session Transfer Token.",
            new OAuth2Error({
              code: errorCode,
              // As today: the error code when Auth0 answered, the request error when it did not.
              message:
                description ??
                ((e as EngineError).statusCode === undefined
                  ? causeOf(e)?.message || (e as EngineError).message
                  : errorCode)
            })
          );
        }
        if (isDiscoveryShaped(e)) {
          return new CustomTokenExchangeError(
            CustomTokenExchangeErrorCode.EXCHANGE_FAILED,
            "Failed to discover authorization server metadata.",
            new OAuth2Error({
              code: "discovery_error",
              message: (e as EngineError).message
            })
          );
        }
        return e;

      case "backchannelAuthentication":
        if (code === "backchannel_authentication_error") {
          return new BackchannelAuthenticationError({
            cause: oauth2ErrorFrom(e)
          });
        }
        break;

      case "backchannelLogout":
        if (
          code === "backchannel_logout_error" ||
          code === "verify_logout_token_error" ||
          // jose verification errors (`ERR_JWT_EXPIRED`, `ERR_JWS_SIGNATURE_VERIFICATION_FAILED`, ...).
          code?.startsWith("ERR_J")
        ) {
          return new BackchannelLogoutError((e as EngineError).message);
        }
        break;

      case "anonymous":
        if (code === "anonymous_session_expired") {
          return mapAnonymousErrorCode("session_expired");
        }
        if (
          (e as { name?: unknown }).name === "AnonymousSessionError" &&
          code
        ) {
          const cause = causeOf(e);
          return mapAnonymousErrorCode(
            code,
            cause?.error_description || undefined,
            cause
          );
        }
        return e;

      case "setup":
      case "login":
        // Login failures become the route's 500 response; nothing to map.
        return e;
    }

    return isDiscoveryShaped(e) ? new DiscoveryError() : e;
  }

  async function callEngine<T>(
    operation: EngineOperation,
    fn: () => T | Promise<T>,
    ctx?: EngineErrorContext
  ): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      throw await toSdkError(e, operation, ctx);
    }
  }

  return { callEngine, toSdkError };
}
