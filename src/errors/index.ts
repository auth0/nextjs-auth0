export { SdkError } from "./sdk-error.js";

export {
  OAuth2Error,
  DiscoveryError,
  MissingStateError,
  InvalidStateError,
  InvalidConfigurationError,
  AuthorizationError,
  AuthorizationCodeGrantRequestError,
  AuthorizationCodeGrantError,
  BackchannelLogoutError,
  BackchannelAuthenticationNotSupportedError,
  BackchannelAuthenticationError,
  AccessTokenError,
  AccessTokenErrorCode,
  AccessTokenForConnectionError,
  AccessTokenForConnectionErrorCode,
  CustomTokenExchangeError,
  CustomTokenExchangeErrorCode
} from "./oauth-errors.js";

export { DPoPError, DPoPErrorCode } from "./dpop-errors.js";

export {
  MyAccountApiError,
  ConnectAccountError,
  ConnectAccountErrorCodes
} from "./my-account-errors.js";

export {
  MfaGetAuthenticatorsError,
  MfaChallengeError,
  MfaVerifyError,
  MfaEnrollmentError,
  MfaNoAvailableFactorsError,
  MfaRequiredError,
  MfaTokenExpiredError,
  MfaTokenInvalidError,
  InvalidRequestError,
  type MfaApiErrorResponse,
  type MfaRequirements
} from "./mfa-errors.js";
