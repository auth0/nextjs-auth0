import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import nock from 'nock';
import { CookieJar } from 'tough-cookie';
import {
  CallbackOptions,
  ConfigParameters,
  LoginOptions,
  LogoutOptions,
  ProfileOptions,
  WithPageAuthRequiredOptions,
  initAuth0,
  AccessTokenRequest,
  Claims,
  OnError,
  Handlers
} from '../../src';
import { codeExchange, discovery, jwksEndpoint, userInfo } from './oidc-nocks';
import { jwks, makeIdToken } from '../auth0-session/fixtures/cert';
import { start, stop } from './server';
import { encodeState } from '../../src/auth0-session/hooks/get-login-state';
import { post, toSignedCookieJar } from '../auth0-session/fixtures/helpers';

export type SetupOptions = {
  idTokenClaims?: Claims;
  callbackOptions?: CallbackOptions;
  loginOptions?: LoginOptions;
  logoutOptions?: LogoutOptions;
  profileOptions?: ProfileOptions;
  withPageAuthRequiredOptions?: WithPageAuthRequiredOptions;
  getAccessTokenOptions?: AccessTokenRequest;
  onError?: OnError;
  discoveryOptions?: Record<string, string>;
  userInfoPayload?: Record<string, string>;
  userInfoToken?: string;
  asyncProps?: boolean;
};

const defaultOnError: OnError = (_req, res, error) => {
  res.statusMessage = error.message;
  res.status(error.status || 500).end(error.message);
};

export const setup = async (
  config: ConfigParameters,
  {
    idTokenClaims,
    callbackOptions,
    logoutOptions,
    loginOptions,
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
  discovery(config, discoveryOptions);
  jwksEndpoint(config, jwks);
  codeExchange(config, await makeIdToken({ iss: 'https://acme.auth0.local/', ...idTokenClaims }));
  userInfo(config, userInfoToken, userInfoPayload);
  const {
    handleAuth,
    handleCallback,
    handleLogin,
    handleLogout,
    handleProfile,
    getSession,
    updateUser,
    getAccessToken,
    withApiAuthRequired,
    withPageAuthRequired
  } = await initAuth0(config);
  const handlers: Partial<Handlers> = { onError };
  if (callbackOptions) {
    handlers.callback = (req, res) => handleCallback(req, res, callbackOptions);
  }
  if (loginOptions) {
    handlers.login = (req, res) => handleLogin(req, res, loginOptions);
  }
  if (logoutOptions) {
    handlers.logout = (req, res) => handleLogout(req, res, logoutOptions);
  }
  if (profileOptions) {
    handlers.profile = (req, res) => handleProfile(req, res, profileOptions);
  }
  global.handleAuth = handleAuth.bind(null, handlers);
  global.getSession = getSession;
  global.updateUser = updateUser;
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
  delete global.updateUser;
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
  const cookieJar = await toSignedCookieJar({ state, nonce }, baseUrl);
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
