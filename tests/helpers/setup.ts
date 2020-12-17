import { CallbackOptions, ConfigParameters, LoginOptions, LogoutOptions } from '../../src/auth0-session';
import { codeExchange, discovery, jwksEndpoint, userInfo } from './oidc-nocks';
import { jwks, makeIdToken } from '../auth0-session/fixture/cert';
import { initAuth0 } from '../../src';
import { start, stop } from './server';
import { Claims } from '../../src/session';
import { ProfileOptions } from '../../src/handlers';
import nock = require('nock');

export type SetupOptions = {
  idTokenClaims?: Claims;
  callbackOptions?: CallbackOptions;
  loginOptions?: LoginOptions;
  logoutOptions?: LogoutOptions;
  profileOptions?: ProfileOptions;
  discoveryOptions?: object;
  userInfoPayload?: object;
};

export const setup = async (
  config: ConfigParameters,
  {
    idTokenClaims,
    callbackOptions,
    logoutOptions,
    loginOptions = { returnTo: '/custom-url' },
    profileOptions,
    discoveryOptions,
    userInfoPayload = {}
  }: SetupOptions = {}
): Promise<string> => {
  discovery(config, discoveryOptions);
  jwksEndpoint(config, jwks);
  codeExchange(config, makeIdToken({ iss: 'https://acme.auth0.local/', ...idTokenClaims }));
  userInfo(config, 'eyJz93a...k4laUWw', userInfoPayload);
  const { handleAuth, handleCallback, handleLogin, handleLogout, handleProfile, getSession } = await initAuth0(config);
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
  return start();
};

export const teardown = async (): Promise<void> => {
  nock.cleanAll();
  await stop();
  delete (global as any).getSession;
  delete (global as any).handleAuth;
};
