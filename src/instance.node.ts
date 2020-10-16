import { NextApiRequest, NextApiResponse } from 'next';
import onHeaders from 'on-headers';
import {
  ConfigParameters,
  getConfig,
  CookieStore,
  TransientCookieHandler,
  logoutHandler,
  callbackHandler,
  clientFactory
} from './auth0-session';
import { profileHandler, requireAuthentication, tokenCache, sessionHandler, loginHandler } from './handlers';
import { fromJson } from './session/session';
import SessionCache from './session/store';

export default function createInstance(params: ConfigParameters) {
  const config = getConfig(params);
  const getClient = clientFactory(config);
  const transientHandler = new TransientCookieHandler(config);
  const cookieStore = new CookieStore(config);
  const sessionCache = new SessionCache(config);

  const applyCookies = (fn: Function) => (req: NextApiRequest, res: NextApiResponse, ...args: []) => {
    if (!sessionCache.has(req)) {
      const [json, iat] = cookieStore.read(req);
      sessionCache.set(req, fromJson(json));
      onHeaders(res, () => cookieStore.save(req, res, sessionCache.get(req), iat));
    }
    return fn(req, res, ...args);
  };

  return {
    handleLogin: applyCookies(loginHandler(config, getClient, transientHandler)),
    handleLogout: applyCookies(logoutHandler(config, getClient, sessionCache)),
    handleCallback: applyCookies(callbackHandler(config, getClient, sessionCache, transientHandler)),
    handleProfile: applyCookies(profileHandler(config, sessionCache, getClient)),
    requireAuthentication: applyCookies(requireAuthentication(sessionCache)),
    tokenCache: applyCookies(tokenCache(getClient, config, sessionCache)),
    getSession: applyCookies(sessionHandler(sessionCache))
  };
}
