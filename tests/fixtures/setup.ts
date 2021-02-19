import nock = require('nock');
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
  GetAccessTokenResult
} from '../../src';
import { codeExchange, discovery, jwksEndpoint, userInfo } from './oidc-nocks';
import { jwks, makeIdToken } from '../auth0-session/fixtures/cert';
import { start, stop } from './server';
import { encodeState } from '../../src/auth0-session/hooks/get-login-state';
import { post, toSignedCookieJar } from '../auth0-session/fixtures/helpers';
import { NextApiRequest, NextApiResponse } from 'next';

export type SetupOptions = {
  idTokenClaims?: Claims;
  callbackOptions?: CallbackOptions;
  loginOptions?: LoginOptions;
  logoutOptions?: LogoutOptions;
  profileOptions?: ProfileOptions;
  withPageAuthRequiredOptions?: WithPageAuthRequiredOptions;
  getAccessTokenOptions?: AccessTokenRequest;
  discoveryOptions?: object;
  userInfoPayload?: object;
  userInfoToken?: string;
};

export const setup = async (
  config: ConfigParameters,
  {
    idTokenClaims,
    callbackOptions,
    logoutOptions,
    loginOptions = { returnTo: '/custom-url' },
    profileOptions,
    withPageAuthRequiredOptions,
    getAccessTokenOptions,
    discoveryOptions,
    userInfoPayload = {},
    userInfoToken = 'eyJz93a...k4laUWw'
  }: SetupOptions = {}
): Promise<string> => {
  discovery(config, discoveryOptions);
  jwksEndpoint(config, jwks);
  codeExchange(config, makeIdToken({ iss: 'https://acme.auth0.local/', ...idTokenClaims }));
  userInfo(config, userInfoToken, userInfoPayload);
  const {
    handleAuth,
    handleCallback,
    handleLogin,
    handleLogout,
    handleProfile,
    getSession,
    getAccessToken,
    withApiAuthRequired,
    withPageAuthRequired
  } = await initAuth0(config);
  (global as any).handleAuth = handleAuth.bind(null, {
    async callback(req, res) {
      try {
        await handleCallback(req, res, callbackOptions);
      } catch (error) {
        res.statusMessage = error.message;
        res.status(error.status || 500).end(error.message);
      }
    },
    async login(req, res) {
      try {
        await handleLogin(req, res, loginOptions);
      } catch (error) {
        res.statusMessage = error.message;
        res.status(error.status || 500).end(error.message);
      }
    },
    async logout(req, res) {
      try {
        await handleLogout(req, res, logoutOptions);
      } catch (error) {
        res.status(error.status || 500).end(error.message);
      }
    },
    async profile(req, res) {
      try {
        await handleProfile(req, res, profileOptions);
      } catch (error) {
        res.statusMessage = error.message;
        res.status(error.status || 500).end(error.message);
      }
    }
  });

  (global as any).getSession = getSession;
  (global as any).withApiAuthRequired = withApiAuthRequired;
  (global as any).withPageAuthRequired = (): any => withPageAuthRequired(withPageAuthRequiredOptions);
  (global as any).withPageAuthRequiredCSR = withPageAuthRequired;
  (global as any).getAccessToken = (req: NextApiRequest, res: NextApiResponse): Promise<GetAccessTokenResult> =>
    getAccessToken(req, res, getAccessTokenOptions);
  return start();
};

export const teardown = async (): Promise<void> => {
  nock.cleanAll();
  await stop();
  delete (global as any).getSession;
  delete (global as any).handleAuth;
  delete (global as any).withApiAuthRequired;
  delete (global as any).withPageAuthRequired;
  delete (global as any).withPageAuthRequiredCSR;
  delete (global as any).getAccessToken;
};

export const login = async (baseUrl: string): Promise<CookieJar> => {
  const nonce = '__test_nonce__';
  const state = encodeState({ returnTo: '/' });
  const cookieJar = toSignedCookieJar({ state, nonce }, baseUrl);
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
