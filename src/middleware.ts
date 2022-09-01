import { NextMiddleware } from 'next/server';
import { default as CookieStore } from './stores/middleware-cookie-store';
import { SessionCache, MiddlewareGetSession as GetSession } from './session/';
import { WithMiddlewareAuthRequired, withMiddlewareAuthRequiredFactory } from './helpers';
import { getConfig, ConfigParameters } from './config';

type Instance = { withMiddlewareAuthRequired: WithMiddlewareAuthRequired; getSession: GetSession };

let instance: Instance;

function getInstance(params?: ConfigParameters): Instance {
  if (instance) {
    return instance;
  }
  instance = _initAuth(params);
  return instance;
}

export const _initAuth = (params?: ConfigParameters): Instance => {
  const { baseConfig, nextConfig } = getConfig(params);

  // Init base layer (with base config)
  const cookieStore = new CookieStore(baseConfig);
  const sessionCache = new SessionCache(baseConfig, cookieStore);

  // Init Next layer (with next config)
  const getSession: GetSession = (req) => sessionCache.get(req);
  const withMiddlewareAuthRequired = withMiddlewareAuthRequiredFactory(nextConfig.routes, () => sessionCache);

  return {
    getSession,
    withMiddlewareAuthRequired
  };
};

export const getSession: GetSession = (...args) => getInstance().getSession(...args);
export const withMiddlewareAuthRequired: WithMiddlewareAuthRequired = (
  middleware?: NextMiddleware,
  params?: ConfigParameters
) => getInstance(params).withMiddlewareAuthRequired(middleware);
