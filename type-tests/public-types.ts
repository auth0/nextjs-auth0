/**
 * TypeScript type contract fixture.
 *
 * Every public type exported from each package entry point is imported and
 * exercised here. Run `pnpm run type-check` (tsc --noEmit) to verify.
 *
 * If a public type is removed, renamed, or a required field is dropped,
 * this file will fail to compile — that is the intended behaviour.
 *
 * DO NOT remove entries from this file without a corresponding
 * major-version changelog entry.
 */

// =============================================================================
// Imports — one block per source module so gaps are easy to spot
// =============================================================================

// Core session / token types
import type {
  AccessTokenSet,
  BackchannelAuthenticationOptions,
  BackchannelAuthenticationResponse,
  GetAccessTokenOptions,
  LogoutStrategy,
  LogoutToken,
  ProxyOptions,
  SessionData,
  SessionDataStore,
  TokenSet,
  User
} from "../src/types/index.js";

// Auth0Client configuration and hook types
import type {
  Auth0ClientOptions,
  BeforeSessionRolledHook,
  BeforeSessionSavedHook,
  CookieOptions,
  OnCallbackHook,
  OnCallbackContext,
  PagesRouterRequest,
  PagesRouterResponse,
  ReadonlyRequestCookies,
  Routes,
  RoutesOptions,
  SessionConfiguration,
  SessionCookieOptions,
  TransactionCookieOptions,
  TransactionState,
  TransactionStoreOptions
} from "../src/types/index.js";

// MCD (Multiple Custom Domains)
import type {
  DiscoveryCacheOptions,
  DomainResolver,
  MCDMetadata
} from "../src/types/mcd.js";

// Authorization / login options
import type {
  AuthorizationParameters,
  StartInteractiveLoginOptions
} from "../src/types/authorize.js";

// Token vault — connection token sets and custom token exchange
import type {
  AccessTokenForConnectionOptions,
  ActClaim,
  ConnectionTokenSet,
  CustomTokenExchangeOptions,
  CustomTokenExchangeResponse
} from "../src/types/token-vault.js";

import {
  GRANT_TYPE_CUSTOM_TOKEN_EXCHANGE,
  SUBJECT_TOKEN_TYPES
} from "../src/types/token-vault.js";

// Connected accounts
import type { ConnectAccountOptions } from "../src/types/connected-accounts.js";
import { RESPONSE_TYPES } from "../src/types/connected-accounts.js";

// MFA types
import type {
  Authenticator,
  AuthenticatorApiResponse,
  ChallengeApiResponse,
  ChallengeResponse,
  EnrollFactorTypeOobOptions,
  EnrollFactorTypeOtpOptions,
  EnrollmentApiResponse,
  EnrollmentResponse,
  EnrollOobOptions,
  EnrollOptions,
  EnrollOtpOptions,
  FactorType,
  MfaClient,
  MfaContext,
  MfaVerifyResponse,
  VerifyMfaOptions,
  VerifyMfaOptionsBase,
  VerifyMfaWithOobOptions,
  VerifyMfaWithOtpOptions,
  VerifyMfaWithRecoveryCodeOptions
} from "../src/types/mfa.js";
import { GRANT_TYPE_MFA_OOB, GRANT_TYPE_MFA_OTP, GRANT_TYPE_MFA_RECOVERY_CODE } from "../src/types/mfa.js";

// Passwordless types
import type {
  PasswordlessClient,
  PasswordlessStartEmailOptions,
  PasswordlessStartOptions,
  PasswordlessStartSmsOptions,
  PasswordlessVerifyEmailOptions,
  PasswordlessVerifyOptions,
  PasswordlessVerifySmsOptions,
  PasswordlessVerifyTokenResponse
} from "../src/types/passwordless.js";
import { GRANT_TYPE_PASSWORDLESS_OTP } from "../src/types/passwordless.js";

// Passwordless DB types
import type {
  PasswordlessDbChallenge,
  PasswordlessDbChallengeEmailOptions,
  PasswordlessDbChallengePhoneOptions,
  PasswordlessDbGetTokenOptions
} from "../src/types/passwordless-db.js";
import type { PasswordlessDbDeliveryMethod } from "../src/types/passwordless-db.js";

// Passkey types
import type {
  PasskeyAuthResponse,
  PasskeyBrowserClient,
  PasskeyChallengeOptions,
  PasskeyChallengeResponse,
  PasskeyClient,
  PasskeyCreationOptionsJSON,
  PasskeyCredentialDescriptorJSON,
  PasskeyEnrollmentChallengeOptions,
  PasskeyEnrollmentChallengeResponse,
  PasskeyEnrollmentVerifyOptions,
  PasskeyEnrollmentVerifyResponse,
  PasskeyGetTokenOptions,
  PasskeyRegisterOptions,
  PasskeyRegisterResponse,
  PasskeyRequestOptionsJSON
} from "../src/types/passkey.js";
import { GRANT_TYPE_PASSKEY } from "../src/types/passkey.js";

// Error type exports (type-only, from errors/)
import type { MfaApiErrorResponse, MfaRequirements } from "../src/errors/mfa-errors.js";
import type { PasswordlessApiErrorResponse } from "../src/errors/passwordless-errors.js";
import type { PasskeyApiErrorResponse } from "../src/errors/passkey-errors.js";

// Runtime values — server entry point
import {
  Auth0Client,
  TransactionStore,
  AbstractSessionStore,
  filterDefaultIdTokenClaims,
  DEFAULT_ID_TOKEN_CLAIMS,
  generateDpopKeyPair
} from "../src/server/index.js";

// Runtime values — client entry point
import {
  useUser,
  getAccessToken,
  withPageAuthRequired as withPageAuthRequiredClient,
  Auth0Provider,
  mfa,
  passwordless,
  passkey,
  serializeCredential
} from "../src/client/index.js";

// Runtime values — testing entry point
import { generateSessionCookie } from "../src/testing/index.js";

// Server-side page auth types (from server/helpers/with-page-auth-required)
import type {
  AppRouterPageRoute,
  AppRouterPageRouteOpts,
  GetServerSidePropsResultWithSession,
  PageRoute,
  WithPageAuthRequired,
  WithPageAuthRequiredAppRouter,
  WithPageAuthRequiredAppRouterOptions,
  WithPageAuthRequiredPageRouter,
  WithPageAuthRequiredPageRouterOptions
} from "../src/server/helpers/with-page-auth-required.js";

// Client-side types
import type { UseUserOptions } from "../src/client/hooks/use-user.js";
import type {
  AccessTokenOptions,
  AccessTokenResponse
} from "../src/client/helpers/get-access-token.js";
import type { WithPageAuthRequiredOptions } from "../src/client/helpers/with-page-auth-required.js";
import type { Auth0ProviderProps } from "../src/client/providers/auth0-provider.js";
import type { ChallengeWithPopupOptions } from "../src/client/mfa/index.js";
import type { AuthCompleteMessage } from "../src/utils/popup-helpers.js";

// Testing types
import type { GenerateSessionCookieConfig } from "../src/testing/generate-session-cookie.js";

// Error classes and codes
import {
  AccessTokenError,
  AccessTokenErrorCode,
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode,
  AuthorizationCodeGrantError,
  AuthorizationCodeGrantRequestError,
  AuthorizationError,
  BackchannelAuthenticationError,
  BackchannelAuthenticationNotSupportedError,
  BackchannelLogoutError,
  ConnectAccountError,
  ConnectAccountErrorCodes,
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode,
  DiscoveryError,
  DomainResolutionError,
  DomainValidationError,
  DPoPError,
  DPoPErrorCode,
  ExecutionContextError,
  InvalidConfigurationError,
  InvalidRequestError,
  InvalidStateError,
  IssuerValidationError,
  MfaChallengeError,
  MfaEnrollmentError,
  MfaGetAuthenticatorsError,
  MfaNoAvailableFactorsError,
  MfaRequiredError,
  MfaTokenExpiredError,
  MfaTokenInvalidError,
  MfaVerifyError,
  MissingStateError,
  MtlsError,
  MtlsErrorCode,
  MyAccountApiError,
  OAuth2Error,
  PasskeyChallengeError,
  PasskeyEnrollmentChallengeError,
  PasskeyEnrollmentVerifyError,
  PasskeyGetTokenError,
  PasskeyRegisterError,
  PasswordlessDbChallengeError,
  PasswordlessDbGetTokenError,
  PasswordlessStartError,
  PasswordlessVerifyError,
  PopupBlockedError,
  PopupCancelledError,
  PopupInProgressError,
  PopupTimeoutError,
  SdkError,
  SessionDomainMismatchError
} from "../src/errors/index.js";

// =============================================================================
// Value / enum presence checks
// These compile only if the exported name still exists.
// =============================================================================

void RESPONSE_TYPES.CODE;
void SUBJECT_TOKEN_TYPES.SUBJECT_TYPE_REFRESH_TOKEN;
void SUBJECT_TOKEN_TYPES.SUBJECT_TYPE_ACCESS_TOKEN;
void GRANT_TYPE_CUSTOM_TOKEN_EXCHANGE;
void GRANT_TYPE_MFA_OTP;
void GRANT_TYPE_MFA_OOB;
void GRANT_TYPE_MFA_RECOVERY_CODE;
void GRANT_TYPE_PASSWORDLESS_OTP;
void GRANT_TYPE_PASSKEY;
void AccessTokenErrorCode.MISSING_SESSION;
void AccessTokenErrorCode.SESSION_EXPIRED;
void AccessTokenForConnectionErrorCode.MISSING_REFRESH_TOKEN;
void AccessTokenForConnectionErrorCode.FAILED_TO_EXCHANGE;
void CustomTokenExchangeErrorCode;
void DPoPErrorCode.DPOP_JKT_CALCULATION_FAILED;
void MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH;
void MtlsErrorCode.MTLS_ENDPOINT_ALIASES_MISSING;
void MtlsErrorCode.MTLS_INCOMPATIBLE_CLIENT_AUTH;
void ConnectAccountErrorCodes.FAILED_TO_INITIATE;
void ConnectAccountErrorCodes.FAILED_TO_COMPLETE;

// Runtime value presence checks — server entry point
void Auth0Client;
void TransactionStore;
void AbstractSessionStore;
void filterDefaultIdTokenClaims;
void DEFAULT_ID_TOKEN_CLAIMS;
void generateDpopKeyPair;

// Runtime value presence checks — client entry point
void useUser;
void getAccessToken;
void withPageAuthRequiredClient;
void Auth0Provider;
void mfa;
void passwordless;
void passkey;
void serializeCredential;

// Runtime value presence checks — testing entry point
void generateSessionCookie;

// =============================================================================
// Error class shape checks
// Constructing an instance verifies the constructor signature is intact.
// Accessing .code / .message / .name verifies the property still exists.
// =============================================================================

// SdkError is abstract — verify it exists as a type and is a base class
{
  const e = new AccessTokenError(AccessTokenErrorCode.MISSING_SESSION, "test") as SdkError;
  e.message;
  e instanceof SdkError;
}

{
  const e = new AccessTokenError(AccessTokenErrorCode.MISSING_SESSION, "msg");
  e.code; e.message;
}

{
  const e = new MfaRequiredError("mfa needed", "tok", undefined, undefined);
  e.mfa_token; e.name;
}

{
  const e = new MtlsError(MtlsErrorCode.MTLS_REQUIRES_CUSTOM_FETCH, "needs custom fetch");
  e.code; e.name;
}

{
  const e = new DPoPError(DPoPErrorCode.DPOP_JKT_CALCULATION_FAILED, "dpop failed");
  e.code;
}

{
  const e = new PasswordlessDbChallengeError("invalid_connection", "Not a database connection.");
  e.error; e.error_description; e.name;
}

{
  const e = new PasswordlessDbGetTokenError("invalid_otp", "OTP invalid.");
  e.error; e.error_description;
}

{
  const e = new PasskeyRegisterError("passkeys_not_enabled", "desc", undefined);
  e.error; e.error_description;
}

{
  const e = new PasswordlessStartError("bad_connection", "not found", undefined);
  e.error; e.error_description;
}

{
  const e = new IssuerValidationError("https://expected/", "https://actual/");
  e.name; e.message;
}

{
  const e = new SessionDomainMismatchError("mismatch");
  e.code; e.name;
}

// These constructors take no arguments or just a message — verify they still exist
void OAuth2Error;
void DiscoveryError;
void MissingStateError;
void InvalidStateError;
void InvalidConfigurationError;
void AuthorizationError;
void AuthorizationCodeGrantRequestError;
void AuthorizationCodeGrantError;
void BackchannelLogoutError;
void BackchannelAuthenticationNotSupportedError;
void BackchannelAuthenticationError;
void AccessTokenForConnectionError;
void CustomTokenExchangeError;
void MyAccountApiError;
void ConnectAccountError;
void MfaGetAuthenticatorsError;
void MfaChallengeError;
void MfaVerifyError;
void MfaEnrollmentError;
void MfaNoAvailableFactorsError;
void MfaTokenExpiredError;
void MfaTokenInvalidError;
void InvalidRequestError;
void PopupBlockedError;
void PopupCancelledError;
void PopupTimeoutError;
void PopupInProgressError;
void ExecutionContextError;
void PasswordlessStartError;
void PasswordlessVerifyError;
void DomainResolutionError;
void DomainValidationError;
void PasskeyChallengeError;
void PasskeyGetTokenError;
void PasskeyEnrollmentChallengeError;
void PasskeyEnrollmentVerifyError;

// =============================================================================
// Interface field-presence checks
// Each assignment fails to compile if a required field is removed or renamed.
// =============================================================================

// TokenSet — accessToken and expiresAt required
const _ts: TokenSet = { accessToken: "at", expiresAt: 0 };
const _tsFull: TokenSet = {
  accessToken: "at", idToken: "id", scope: "openid", requestedScope: "openid",
  refreshToken: "rt", expiresAt: 9999, audience: "https://api.example.com", token_type: "Bearer"
};
void _ts; void _tsFull;

// AccessTokenSet — accessToken, audience, expiresAt required
const _ats: AccessTokenSet = { accessToken: "at", audience: "https://api.example.com", expiresAt: 9999 };
void _ats;

// User — sub required
const _user: User = { sub: "user_123" };
const _userFull: User = {
  sub: "user_123", name: "Test", email: "t@x.com", email_verified: true,
  picture: "https://x.com/p.jpg", org_id: "org_abc", session_expiry: 9999
};
void _user; void _userFull;

// ActClaim
const _act: ActClaim = { sub: "actor_123" };
void _act;

// SessionData — user, tokenSet, internal required
const _session: SessionData = {
  user: { sub: "u" },
  tokenSet: { accessToken: "at", expiresAt: 9999 },
  internal: { sid: "s", createdAt: 1000000 }
};
void _session;

// LogoutToken
const _lt: LogoutToken = { sub: "u", sid: "s", iss: "https://issuer/" };
void _lt;

// ConnectionTokenSet — accessToken, expiresAt, connection required
const _cts: ConnectionTokenSet = { accessToken: "at", expiresAt: 9999, connection: "google-oauth2" };
void _cts;

// GetAccessTokenOptions — all optional
const _gato: GetAccessTokenOptions = {};
const _gatoFull: GetAccessTokenOptions = { refresh: true, scope: "openid", audience: "https://api.example.com", mergeScopes: false };
void _gato; void _gatoFull;

// LogoutStrategy union
const _ls1: LogoutStrategy = "auto";
const _ls2: LogoutStrategy = "oidc";
const _ls3: LogoutStrategy = "v2";
void _ls1; void _ls2; void _ls3;

// BackchannelAuthenticationOptions — bindingMessage and loginHint required
const _bcOpts: BackchannelAuthenticationOptions = {
  bindingMessage: "Confirm on your phone",
  loginHint: { sub: "user_123" }
};
void _bcOpts;

// BackchannelAuthenticationResponse — tokenSet required
const _bcResp: BackchannelAuthenticationResponse = { tokenSet: { accessToken: "at", expiresAt: 9999 } };
void _bcResp;

// CookieOptions — all four fields required
const _co: CookieOptions = { httpOnly: true, sameSite: "lax", secure: true, path: "/" };
void _co;

// SessionCookieOptions — all optional
const _sco: SessionCookieOptions = {};
const _scoFull: SessionCookieOptions = { sameSite: "strict", secure: true, path: "/", domain: "example.com", transient: false };
void _sco; void _scoFull;

// SessionConfiguration — all optional
const _sCfg: SessionConfiguration = {};
const _sCfgFull: SessionConfiguration = { rolling: true, absoluteDuration: 86400, inactivityDuration: 3600 };
void _sCfg; void _sCfgFull;

// TransactionState — state, returnTo, responseType, codeVerifier required
const _txnState: TransactionState = {
  state: "xyz", returnTo: "/dashboard",
  responseType: RESPONSE_TYPES.CODE, codeVerifier: "cv"
};
void _txnState;

// TransactionCookieOptions — all optional
const _tco: TransactionCookieOptions = {};
void _tco;

// TransactionStoreOptions — secret required
const _tso: TransactionStoreOptions = { secret: "s".repeat(32) };
void _tso;

// MCDMetadata — domain and issuer required
const _mcd: MCDMetadata = { domain: "custom.example.com", issuer: "https://custom.example.com/" };
void _mcd;

// DiscoveryCacheOptions — all optional
const _dco: DiscoveryCacheOptions = {};
void _dco;

// AuthorizationParameters — all optional
const _ap: AuthorizationParameters = {};
const _apFull: AuthorizationParameters = { scope: "openid", audience: "https://api.example.com" };
void _ap; void _apFull;

// StartInteractiveLoginOptions — all optional
const _silo: StartInteractiveLoginOptions = {};
void _silo;

// AccessTokenForConnectionOptions — connection required
const _afco: AccessTokenForConnectionOptions = { connection: "google-oauth2" };
void _afco;

// CustomTokenExchangeOptions — subjectToken and subjectTokenType required
const _cteo: CustomTokenExchangeOptions = {
  subjectToken: "ext-token",
  subjectTokenType: "urn:acme:legacy-token"
};
void _cteo;

// CustomTokenExchangeResponse — accessToken, tokenType, expiresIn required
const _cteResp: CustomTokenExchangeResponse = { accessToken: "at", tokenType: "Bearer", expiresIn: 3600 };
void _cteResp;

// ConnectAccountOptions — connection required
const _cao: ConnectAccountOptions = { connection: "github" };
void _cao;

// ProxyOptions — proxyPath, targetBaseUrl, audience, scope required
const _po: ProxyOptions = { proxyPath: "/proxy", targetBaseUrl: "https://api.example.com", audience: "https://api.example.com", scope: "openid" };
void _po;

// PasswordlessDbChallengeEmailOptions — email and connection required
const _pdbcEmail: PasswordlessDbChallengeEmailOptions = { email: "u@example.com", connection: "email-otp" };
void _pdbcEmail;

// PasswordlessDbChallengePhoneOptions — phoneNumber and connection required
const _pdbcPhone: PasswordlessDbChallengePhoneOptions = { phoneNumber: "+15555555555", connection: "sms-otp" };
void _pdbcPhone;

// PasswordlessDbChallenge — authSession required
const _pdbc: PasswordlessDbChallenge = { authSession: "session_abc" };
void _pdbc;

// PasswordlessDbGetTokenOptions — authSession, otp required (no connection field)
const _pdbgto: PasswordlessDbGetTokenOptions = { authSession: "session_abc", otp: "123456" };
void _pdbgto;

// PasswordlessDbDeliveryMethod union
const _pdm1: PasswordlessDbDeliveryMethod = "text";
const _pdm2: PasswordlessDbDeliveryMethod = "voice";
void _pdm1; void _pdm2;

// PasswordlessStartEmailOptions — connection, email, send required
const _pseo: PasswordlessStartEmailOptions = { connection: "email", email: "u@example.com", send: "code" };
void _pseo;

// PasswordlessStartSmsOptions — connection and phoneNumber required
const _psso: PasswordlessStartSmsOptions = { connection: "sms", phoneNumber: "+15555555555" };
void _psso;

// PasswordlessVerifyEmailOptions — connection, email, verificationCode required
const _pveo: PasswordlessVerifyEmailOptions = { connection: "email", email: "u@example.com", verificationCode: "123456" };
void _pveo;

// PasswordlessVerifySmsOptions — connection, phoneNumber, verificationCode required
const _pvso: PasswordlessVerifySmsOptions = { connection: "sms", phoneNumber: "+15555555555", verificationCode: "123456" };
void _pvso;

// PasswordlessVerifyTokenResponse — access_token, token_type, expires_in required
const _pvtr: PasswordlessVerifyTokenResponse = { access_token: "at", token_type: "Bearer", expires_in: 3600 };
void _pvtr;

// FactorType union
const _ft1: FactorType = "otp";
const _ft2: FactorType = "sms";
void _ft1; void _ft2;

// MFAVerify options union — mfaToken required
const _vmOtp: VerifyMfaWithOtpOptions = { mfaToken: "tok", otp: "123456" };
const _vmOob: VerifyMfaWithOobOptions = { mfaToken: "tok", oobCode: "oob", bindingCode: "bc" };
const _vmRc: VerifyMfaWithRecoveryCodeOptions = { mfaToken: "tok", recoveryCode: "rc" };
void _vmOtp; void _vmOob; void _vmRc;

// =============================================================================
// Interface-implementor checks
// These verify that the structural contract for implementable interfaces
// (SessionDataStore, DomainResolver, hooks) hasn't changed.
// =============================================================================

class MinimalSessionStore implements SessionDataStore {
  async get(_id: string): Promise<SessionData | null> { return null; }
  async set(_id: string, _s: SessionData): Promise<void> {}
  async delete(_id: string): Promise<void> {}
}
void MinimalSessionStore;

const _beforeSessionSaved: BeforeSessionSavedHook = async (session) => session;
void _beforeSessionSaved;

const _beforeSessionRolled: BeforeSessionRolledHook = async () => true;
void _beforeSessionRolled;

const _onCallback: OnCallbackHook = async (error, ctx, session) => {
  void error; void ctx; void session;
  return undefined as any; // NextResponse — not imported to avoid next/server dep
};
void _onCallback;

const _domainResolver: DomainResolver = async (req) => {
  void req;
  return "custom.example.com";
};
void _domainResolver;

// =============================================================================
// Type alias reachability — confirm re-exported type-only names are accessible
// These compile only if the export still exists; no runtime impact.
// =============================================================================

type _PagesRouterRequestCheck = PagesRouterRequest;
type _PagesRouterResponseCheck = PagesRouterResponse;
type _ReadonlyRequestCookiesCheck = ReadonlyRequestCookies;
type _RoutesCheck = Routes;
type _RoutesOptionsCheck = RoutesOptions;
type _Auth0ClientOptionsCheck = Auth0ClientOptions;
type _OnCallbackContextCheck = OnCallbackContext;
type _VerifyMfaOptionsCheck = VerifyMfaOptions;
type _VerifyMfaOptionsBaseCheck = VerifyMfaOptionsBase;
type _EnrollOptionsCheck = EnrollOptions;
type _EnrollmentResponseCheck = EnrollmentResponse;
type _PasswordlessStartOptionsCheck = PasswordlessStartOptions;
type _PasswordlessVerifyOptionsCheck = PasswordlessVerifyOptions;

// Client interface reachability (structural — just confirming the types exist)
type _MfaClientCheck = MfaClient;
type _PasswordlessClientCheck = PasswordlessClient;
type _PasskeyClientCheck = PasskeyClient;
type _PasskeyBrowserClientCheck = PasskeyBrowserClient;
type _AuthenticatorCheck = Authenticator;
type _ChallengeResponseCheck = ChallengeResponse;
type _MfaContextCheck = MfaContext;
type _MfaVerifyResponseCheck = MfaVerifyResponse;
type _AuthenticatorApiResponseCheck = AuthenticatorApiResponse;
type _ChallengeApiResponseCheck = ChallengeApiResponse;
type _EnrollmentApiResponseCheck = EnrollmentApiResponse;
type _EnrollOtpOptionsCheck = EnrollOtpOptions;
type _EnrollOobOptionsCheck = EnrollOobOptions;
type _EnrollFactorTypeOtpOptionsCheck = EnrollFactorTypeOtpOptions;
type _EnrollFactorTypeOobOptionsCheck = EnrollFactorTypeOobOptions;
type _PasskeyRegisterOptionsCheck = PasskeyRegisterOptions;
type _PasskeyRegisterResponseCheck = PasskeyRegisterResponse;
type _PasskeyChallengeOptionsCheck = PasskeyChallengeOptions;
type _PasskeyChallengeResponseCheck = PasskeyChallengeResponse;
type _PasskeyGetTokenOptionsCheck = PasskeyGetTokenOptions;
type _PasskeyAuthResponseCheck = PasskeyAuthResponse;
type _PasskeyCreationOptionsJSONCheck = PasskeyCreationOptionsJSON;
type _PasskeyRequestOptionsJSONCheck = PasskeyRequestOptionsJSON;
type _PasskeyCredentialDescriptorJSONCheck = PasskeyCredentialDescriptorJSON;
type _PasskeyEnrollmentChallengeOptionsCheck = PasskeyEnrollmentChallengeOptions;
type _PasskeyEnrollmentChallengeResponseCheck = PasskeyEnrollmentChallengeResponse;
type _PasskeyEnrollmentVerifyOptionsCheck = PasskeyEnrollmentVerifyOptions;
type _PasskeyEnrollmentVerifyResponseCheck = PasskeyEnrollmentVerifyResponse;

// Server-side page auth helpers
type _GetServerSidePropsResultWithSessionCheck = GetServerSidePropsResultWithSession;
type _PageRouteCheck = PageRoute<Record<string, unknown>>;
type _AppRouterPageRouteOptsCheck = AppRouterPageRouteOpts;
type _AppRouterPageRouteCheck = AppRouterPageRoute<Record<string, unknown>>;
type _WithPageAuthRequiredPageRouterOptionsCheck = WithPageAuthRequiredPageRouterOptions<Record<string, unknown>>;
type _WithPageAuthRequiredPageRouterCheck = WithPageAuthRequiredPageRouter;
type _WithPageAuthRequiredAppRouterOptionsCheck = WithPageAuthRequiredAppRouterOptions;
type _WithPageAuthRequiredAppRouterCheck = WithPageAuthRequiredAppRouter;
type _WithPageAuthRequiredCheck = WithPageAuthRequired;

// Client-side types
type _UseUserOptionsCheck = UseUserOptions;
type _AccessTokenOptionsCheck = AccessTokenOptions;
type _AccessTokenResponseCheck = AccessTokenResponse;
type _WithPageAuthRequiredOptionsCheck = WithPageAuthRequiredOptions;
type _Auth0ProviderPropsCheck = Auth0ProviderProps;
type _ChallengeWithPopupOptionsCheck = ChallengeWithPopupOptions;
type _AuthCompleteMessageCheck = AuthCompleteMessage;

// Error type-only exports
type _MfaApiErrorResponseCheck = MfaApiErrorResponse;
type _MfaRequirementsCheck = MfaRequirements;
type _PasswordlessApiErrorResponseCheck = PasswordlessApiErrorResponse;
type _PasskeyApiErrorResponseCheck = PasskeyApiErrorResponse;

// Testing types
type _GenerateSessionCookieConfigCheck = GenerateSessionCookieConfig;

// Suppress unused type warnings
declare const _unused: [
  _PagesRouterRequestCheck,
  _PagesRouterResponseCheck,
  _ReadonlyRequestCookiesCheck,
  _RoutesCheck,
  _RoutesOptionsCheck,
  _Auth0ClientOptionsCheck,
  _OnCallbackContextCheck,
  _VerifyMfaOptionsCheck,
  _VerifyMfaOptionsBaseCheck,
  _EnrollOptionsCheck,
  _EnrollmentResponseCheck,
  _PasswordlessStartOptionsCheck,
  _PasswordlessVerifyOptionsCheck,
  _MfaClientCheck,
  _PasswordlessClientCheck,
  _PasskeyClientCheck,
  _PasskeyBrowserClientCheck,
  _AuthenticatorCheck,
  _ChallengeResponseCheck,
  _MfaContextCheck,
  _MfaVerifyResponseCheck,
  _AuthenticatorApiResponseCheck,
  _ChallengeApiResponseCheck,
  _EnrollmentApiResponseCheck,
  _EnrollOtpOptionsCheck,
  _EnrollOobOptionsCheck,
  _EnrollFactorTypeOtpOptionsCheck,
  _EnrollFactorTypeOobOptionsCheck,
  _PasskeyRegisterOptionsCheck,
  _PasskeyRegisterResponseCheck,
  _PasskeyChallengeOptionsCheck,
  _PasskeyChallengeResponseCheck,
  _PasskeyGetTokenOptionsCheck,
  _PasskeyAuthResponseCheck,
  _PasskeyCreationOptionsJSONCheck,
  _PasskeyRequestOptionsJSONCheck,
  _PasskeyCredentialDescriptorJSONCheck,
  _PasskeyEnrollmentChallengeOptionsCheck,
  _PasskeyEnrollmentChallengeResponseCheck,
  _PasskeyEnrollmentVerifyOptionsCheck,
  _PasskeyEnrollmentVerifyResponseCheck,
  _GetServerSidePropsResultWithSessionCheck,
  _PageRouteCheck,
  _AppRouterPageRouteOptsCheck,
  _AppRouterPageRouteCheck,
  _WithPageAuthRequiredPageRouterOptionsCheck,
  _WithPageAuthRequiredPageRouterCheck,
  _WithPageAuthRequiredAppRouterOptionsCheck,
  _WithPageAuthRequiredAppRouterCheck,
  _WithPageAuthRequiredCheck,
  _UseUserOptionsCheck,
  _AccessTokenOptionsCheck,
  _AccessTokenResponseCheck,
  _WithPageAuthRequiredOptionsCheck,
  _Auth0ProviderPropsCheck,
  _ChallengeWithPopupOptionsCheck,
  _AuthCompleteMessageCheck,
  _GenerateSessionCookieConfigCheck,
  _MfaApiErrorResponseCheck,
  _MfaRequirementsCheck,
  _PasswordlessApiErrorResponseCheck,
  _PasskeyApiErrorResponseCheck
];
