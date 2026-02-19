export { Auth0Client } from "./client.js";

export { TransactionStore } from "./transaction-store.js";

export { AbstractSessionStore } from "./session/abstract-session-store.js";

export { filterDefaultIdTokenClaims, DEFAULT_ID_TOKEN_CLAIMS } from "./user.js";

// MFA error classes for handling MFA step-up authentication
export {
  MfaRequiredError,
  MfaTokenExpiredError,
  MfaTokenInvalidError
} from "../errors/index.js";

// MFA types for error handling
export type { MfaRequirements } from "../errors/index.js";

export {
  GetServerSidePropsResultWithSession,
  WithPageAuthRequired,
  WithPageAuthRequiredPageRouterOptions,
  WithPageAuthRequiredAppRouterOptions,
  PageRoute,
  AppRouterPageRouteOpts,
  AppRouterPageRoute,
  WithPageAuthRequiredPageRouter,
  WithPageAuthRequiredAppRouter
} from "./helpers/with-page-auth-required.js";

// Instrumentation types for logger configuration
export type {
  LogLevel,
  InstrumentationEvent,
  InstrumentationLogger
} from "../types/instrumentation.js";
