import { NextMiddleware, NextRequest, NextResponse } from 'next/server';
import { default as CookieStore } from './auth0-session/cookie-store';
import MiddlewareCookies from './utils/middleware-cookies';
import { SessionCache, Session } from './session/';
import {
  WithMiddlewareAuthRequired,
  default as withMiddlewareAuthRequiredFactory
} from './helpers/with-middleware-auth-required';
import { getConfig, ConfigParameters } from './config';

export type Instance = { withMiddlewareAuthRequired: WithMiddlewareAuthRequired; getSession: GetSession };

export type GetSession = (req: NextRequest, res: NextResponse) => Promise<Session | null | undefined>;

export type InitAuth0 = (params?: ConfigParameters) => Instance;

export { WithMiddlewareAuthRequired };

let instance: Instance;

function getInstance(params?: ConfigParameters): Instance {
  if (instance) {
    return instance;
  }
  instance = initAuth(params);
  return instance;
}

export const initAuth: InitAuth0 = (params?) => {
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
