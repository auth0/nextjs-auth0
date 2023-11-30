import { IncomingMessage, ServerResponse } from 'http';
import { NextApiHandler, NextApiRequest, NextApiResponse } from 'next';
import nock from 'nock';
import { CookieJar } from 'tough-cookie';
import {
  CallbackOptions,
  ConfigParameters,
  LoginOptions,
  LogoutOptions,
  ProfileOptions,
  WithPageAuthRequiredPageRouterOptions,
  initAuth0,
  AccessTokenRequest,
  Claims,
  PageRouterOnError,
  HandleLogin,
  HandleLogout,
  HandleCallback,
  HandleProfile,
  HandleBackchannelLogout
} from '../../src';
import { codeExchange, discovery, jwksEndpoint, userInfo } from './oidc-nocks';
import { jwks, makeIdToken } from '../auth0-session/fixtures/cert';
import { start, stop } from './server';
import { encodeState } from '../../src/auth0-session/utils/encoding';
import { post, toSignedCookieJar } from '../auth0-session/fixtures/helpers';

export type SetupOptions = {
  idTokenClaims?: Claims;
  callbackHandler?: HandleCallback;
  callbackOptions?: CallbackOptions;
  loginHandler?: HandleLogin;
  loginOptions?: LoginOptions;
  logoutHandler?: HandleLogout;
  logoutOptions?: LogoutOptions;
  profileHandler?: HandleProfile;
  backchannelLogoutHandler?: HandleBackchannelLogout;
  profileOptions?: ProfileOptions;
  withPageAuthRequiredOptions?: WithPageAuthRequiredPageRouterOptions;
  getAccessTokenOptions?: AccessTokenRequest;
  onError?: PageRouterOnError;
  discoveryOptions?: Record<string, any>;
  userInfoPayload?: Record<string, string>;
  userInfoToken?: string;
  asyncProps?: boolean;
};

export const defaultOnError: PageRouterOnError = (_req, res, error) => {
  res.statusMessage = error.message;
  res.status(error.status || 500).end(error.message);
};

export const setupNock = async (
  config: ConfigParameters,
  {
    idTokenClaims,
    discoveryOptions,
    userInfoPayload = {},
    userInfoToken = 'eyJz93a...k4laUWw'
  }: Pick<SetupOptions, 'idTokenClaims' | 'discoveryOptions' | 'userInfoPayload' | 'userInfoToken'> = {}
) => {
  discovery(config, discoveryOptions);
  jwksEndpoint(config, jwks);
  codeExchange(config, await makeIdToken({ iss: 'https://acme.auth0.local/', ...idTokenClaims }));
  userInfo(config, userInfoToken, userInfoPayload);
};

export const setup = async (
  config: ConfigParameters,
  {
    idTokenClaims,
    callbackHandler,
    callbackOptions,
    logoutHandler,
    logoutOptions,
    loginHandler,
    loginOptions,
    profileHandler,
    backchannelLogoutHandler,
    profileOptions,
    withPageAuthRequiredOptions,
    onError = defaultOnError,
    getAccessTokenOptions,
    discoveryOptions,
    userInfoPayload = {},
    userInfoToken = 'eyJz93a...k4laUWw',
    asyncProps
  }: SetupOptions = {}
): Promise<string> => {
  await setupNock(config, { idTokenClaims, discoveryOptions, userInfoPayload, userInfoToken });
  const {
    handleAuth,
    handleCallback,
    handleLogin,
    handleLogout,
    handleBackchannelLogout,
    handleProfile,
    getSession,
    touchSession,
    updateSession,
    getAccessToken,
    withApiAuthRequired,
    withPageAuthRequired
  } = initAuth0(config);
  const callback: NextApiHandler = (...args) => (callbackHandler || handleCallback)(...args, callbackOptions);
  const login: NextApiHandler = (...args) => (loginHandler || handleLogin)(...args, loginOptions);
  const logout: NextApiHandler = (...args) => (logoutHandler || handleLogout)(...args, logoutOptions);
  const profile: NextApiHandler = (...args) => (profileHandler || handleProfile)(...args, profileOptions);
  const backchannelLogout: NextApiHandler = (...args) => (backchannelLogoutHandler || handleBackchannelLogout)(...args);
  const handlers: { [key: string]: NextApiHandler } = {
    onError: onError as any,
    callback,
    login,
    logout,
    profile,
    'backchannel-logout:': backchannelLogout
  };
  global.handleAuth = handleAuth.bind(null, handlers);
  global.getSession = getSession;
  global.touchSession = touchSession;
  global.updateSession = updateSession;
  global.withApiAuthRequired = withApiAuthRequired;
  global.withPageAuthRequired = (): any => withPageAuthRequired(withPageAuthRequiredOptions);
  global.withPageAuthRequiredCSR = withPageAuthRequired;
  global.getAccessToken = (req: IncomingMessage | NextApiRequest, res: ServerResponse | NextApiResponse) =>
    getAccessToken(req, res, getAccessTokenOptions);
  global.onError = onError;
  global.asyncProps = asyncProps;
  return start();
};

export const teardown = async (): Promise<void> => {
  nock.cleanAll();
  await stop();
  delete global.getSession;
  delete global.touchSession;
  delete global.updateSession;
  delete global.handleAuth;
  delete global.withApiAuthRequired;
  delete global.withPageAuthRequired;
  delete global.withPageAuthRequiredCSR;
  delete global.getAccessToken;
  delete global.onError;
  delete global.asyncProps;
};

export const login = async (baseUrl: string): Promise<CookieJar> => {
  const nonce = '__test_nonce__';
  const state = encodeState({ returnTo: '/' });
  const cookieJar = await toSignedCookieJar({ auth_verification: JSON.stringify({ state, nonce }) }, baseUrl);
  await post(baseUrl, '/api/auth/callback', {
    fullResponse: true,
    body: {
      state,
      code: 'code'
    },
    cookieJar
  });
  return cookieJar;
};
