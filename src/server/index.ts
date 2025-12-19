export { Auth0Client } from "./client.js";

export { TransactionStore } from "./transaction-store.js";

export { AbstractSessionStore } from "./session/abstract-session-store.js";

export { filterDefaultIdTokenClaims, DEFAULT_ID_TOKEN_CLAIMS } from "./user.js";

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
