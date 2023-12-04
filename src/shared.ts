import { SessionStore as GenericSessionStore, SessionPayload } from './auth0-session';
import {
  HandleAuth,
  HandleLogin,
  HandleProfile,
  HandleLogout,
  HandleCallback,
  HandleBackchannelLogout
} from './handlers';
import { SessionCache, GetSession, GetAccessToken, Session, TouchSession, UpdateSession } from './session/';
import { WithApiAuthRequired, WithPageAuthRequired } from './helpers';
import { ConfigParameters } from './config';
import { WithMiddlewareAuthRequired } from './helpers/with-middleware-auth-required';
import version from './version';

export const telemetry = { name: 'nextjs-auth0', version };

/**
 * The SDK server instance.
 *
 * This is created for you when you use the named exports, or you can create your own using {@link InitAuth0}.
 *
 * See {@link ConfigParameters} for more info.
 *
 * @category Server
 */
export interface Auth0Server {
  /**
   * Session getter.
   */
  getSession: GetSession;

  /**
   * Update the expiry of a rolling session when autoSave is disabled.
   */
  touchSession: TouchSession;

  /**
   * Append properties to the user.
   */
  updateSession: UpdateSession;

  /**
   * Access token getter.
   */
  getAccessToken: GetAccessToken;

  /**
   * Login handler which will redirect the user to Auth0.
   */
  handleLogin: HandleLogin;

  /**
   * Callback handler which will complete the transaction and create a local session.
   */
  handleCallback: HandleCallback;

  /**
   * Logout handler which will clear the local session and the Auth0 session.
   */
  handleLogout: HandleLogout;

  /**
   * Logout handler which will clear the local session and the Auth0 session.
   */
  handleBackchannelLogout: HandleBackchannelLogout;

  /**
   * Profile handler which return profile information about the user.
   */
  handleProfile: HandleProfile;

  /**
   * Helper that adds auth to an API route.
   */
  withApiAuthRequired: WithApiAuthRequired;

  /**
   * Helper that adds auth to a Page route.
   */
  withPageAuthRequired: WithPageAuthRequired;

  /**
   * Create the main handlers for your api routes.
   */
  handleAuth: HandleAuth;

  /**
   * Add auth to your middleware functions.
   */
  withMiddlewareAuthRequired: WithMiddlewareAuthRequired;
}

export {
  AuthError,
  AccessTokenErrorCode,
  AccessTokenError,
  HandlerError,
  CallbackHandlerError,
  LoginHandlerError,
  LogoutHandlerError,
  ProfileHandlerError
} from './utils/errors';

export {
  Handlers,
  LoginOptions,
  LogoutOptions,
  GetLoginState,
  GetLoginStatePageRoute,
  GetLoginStateAppRoute,
  ProfileOptions,
  CallbackOptions,
  AfterCallback,
  AfterCallbackPageRoute,
  AfterCallbackAppRoute,
  AfterRefetch,
  AfterRefetchPageRoute,
  AfterRefetchAppRoute,
  AppRouterOnError,
  PageRouterOnError,
  AppRouteHandlerFnContext,
  NextAppRouterHandler,
  NextPageRouterHandler,
  AppRouterHandler,
  PageRouterHandler
} from './handlers';

export {
  AppRouterPageRouteOpts,
  AppRouterPageRoute,
  WithPageAuthRequiredPageRouter,
  WithPageAuthRequiredAppRouter,
  GetServerSidePropsResultWithSession,
  WithPageAuthRequiredPageRouterOptions,
  WithPageAuthRequiredAppRouterOptions,
  PageRoute,
  AppRouteHandlerFn,
  WithApiAuthRequiredAppRoute,
  WithApiAuthRequiredPageRoute
} from './helpers';

export {
  AccessTokenRequest,
  GetAccessTokenResult,
  Claims,
  AfterRefresh,
  AfterRefreshPageRoute,
  AfterRefreshAppRoute
} from './session';

export {
  MissingStateCookieError,
  MalformedStateCookieError,
  MissingStateParamError,
  IdentityProviderError,
  ApplicationError
} from './auth0-session';

export {
  ConfigParameters,
  HandleAuth,
  HandleLogin,
  HandleProfile,
  HandleLogout,
  HandleCallback,
  HandleBackchannelLogout,
  WithApiAuthRequired,
  WithPageAuthRequired,
  SessionCache,
  GetSession,
  TouchSession,
  UpdateSession,
  GetAccessToken,
  Session
};

export type SessionStore = GenericSessionStore<Session>;
export type SessionStorePayload = SessionPayload<Session>;
