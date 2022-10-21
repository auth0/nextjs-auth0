import { NextMiddleware, NextRequest, NextResponse } from 'next/server';
import { default as CookieStore } from './auth0-session/cookie-store';
import MiddlewareCookies from './utils/middleware-cookies';
import Session from './session/session';
import SessionCache from './session/cache';
import {
  WithMiddlewareAuthRequired,
  default as withMiddlewareAuthRequiredFactory
} from './helpers/with-middleware-auth-required';
import { getConfig, ConfigParameters } from './config';
import { setIsUsingNamedExports, setIsUsingOwnInstance } from './utils/instance-check';

export type Instance = { withMiddlewareAuthRequired: WithMiddlewareAuthRequired; getSession: GetSession };

export type GetSession = (req: NextRequest, res: NextResponse) => Promise<Session | null | undefined>;

export type InitAuth0 = (params?: ConfigParameters) => Instance;

export { WithMiddlewareAuthRequired };

let instance: Instance;

function getInstance(params?: ConfigParameters): Instance {
  setIsUsingNamedExports();
  if (instance) {
    return instance;
  }
  instance = _initAuth0(params);
  return instance;
}

export const initAuth0: InitAuth0 = (params?) => {
  setIsUsingOwnInstance();
  return _initAuth0(params);
};

const _initAuth0: InitAuth0 = (params?) => {
  const { baseConfig, nextConfig } = getConfig(params);

  // Init base layer (with base config)
  const cookieStore = new CookieStore<NextRequest, NextResponse>(baseConfig, MiddlewareCookies);
  const sessionCache = new SessionCache(baseConfig, cookieStore);

  // Init Next layer (with next config)
  const getSession: GetSession = (req, res) => sessionCache.get(req, res);
  const withMiddlewareAuthRequired = withMiddlewareAuthRequiredFactory(nextConfig.routes, () => sessionCache);

  return {
    getSession,
    withMiddlewareAuthRequired
  };
};

export const getSession: GetSession = (...args) => getInstance().getSession(...args);
export const withMiddlewareAuthRequired: WithMiddlewareAuthRequired = (middleware?: NextMiddleware) =>
  getInstance().withMiddlewareAuthRequired(middleware);
