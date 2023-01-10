import { NextMiddleware, NextRequest, NextResponse } from 'next/server';
import { StatelessSession } from './auth0-session/session/stateless-session';
import { StatefulSession } from './auth0-session/session/stateful-session';
import MiddlewareCookies from './utils/middleware-cookies';
import Session from './session/session';
import SessionCache from './session/cache';
import {
  WithMiddlewareAuthRequired,
  default as withMiddlewareAuthRequiredFactory
} from './helpers/with-middleware-auth-required';
import { getConfig, ConfigParameters } from './config';
import { setIsUsingNamedExports, setIsUsingOwnInstance } from './utils/instance-check';

export type Auth0Edge = { withMiddlewareAuthRequired: WithMiddlewareAuthRequired; getSession: GetSession };

export type GetSession = (req: NextRequest, res: NextResponse) => Promise<Session | null | undefined>;

export type InitAuth0 = (params?: ConfigParameters) => Auth0Edge;

export { WithMiddlewareAuthRequired };

let instance: Auth0Edge;

const genId = () => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

function getInstance(params?: ConfigParameters): Auth0Edge {
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
  const { baseConfig, nextConfig } = getConfig({ ...params, session: { genId, ...params?.session } });

  // Init base layer (with base config)
  const sessionStore = baseConfig.session.store
    ? new StatefulSession<NextRequest, NextResponse, Session>(baseConfig, MiddlewareCookies)
    : new StatelessSession<NextRequest, NextResponse, Session>(baseConfig, MiddlewareCookies);
  const sessionCache = new SessionCache(baseConfig, sessionStore);

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
