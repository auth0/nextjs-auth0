import urlJoin from 'url-join';
import createDebug from '../utils/debug';
import { GetConfig, LogoutOptions } from '../config';
import { SessionCache } from '../session-cache';
import { Auth0Request, Auth0Response } from '../http';
import { GetClient } from '../client/abstract-client';

const debug = createDebug('logout');

export type HandleLogout = (req: Auth0Request, res: Auth0Response, options?: LogoutOptions) => Promise<void>;

export default function logoutHandlerFactory(
  getConfig: GetConfig,
  getClient: GetClient,
  sessionCache: SessionCache
): HandleLogout {
  const getConfigFn = typeof getConfig === 'function' ? getConfig : () => getConfig;
  return async (req, res, options = {}) => {
    const config = await getConfigFn(req);
    const client = await getClient(config);
    let returnURL = options.returnTo || config.routes.postLogoutRedirect;
    debug('logout() with return url: %s', returnURL);

    try {
      new URL(returnURL);
    } catch (_) {
      returnURL = urlJoin(config.baseURL, returnURL);
    }

    const isAuthenticated = await sessionCache.isAuthenticated(req.req, res.res);
    if (!isAuthenticated) {
      debug('end-user already logged out, redirecting to %s', returnURL);
      res.redirect(returnURL);
      return;
    }

    const idToken = await sessionCache.getIdToken(req.req, res.res);
    await sessionCache.delete(req.req, res.res);

    if (!config.idpLogout) {
      debug('performing a local only logout, redirecting to %s', returnURL);
      res.redirect(returnURL);
      return;
    }

    returnURL = await client.endSessionUrl({
      ...options.logoutParams,
      post_logout_redirect_uri: returnURL,
      id_token_hint: idToken
    });

    debug('logging out of identity provider, redirecting to %s', returnURL);
    res.redirect(returnURL);
  };
}
