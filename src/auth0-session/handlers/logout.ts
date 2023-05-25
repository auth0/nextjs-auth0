import url from 'url';
import urlJoin from 'url-join';
import createDebug from '../utils/debug';
import { Config, LogoutOptions } from '../config';
import { ClientFactory } from '../client';
import { SessionCache } from '../session-cache';
import { Auth0Request, Auth0Response } from '../http';

const debug = createDebug('logout');

export type HandleLogout = (req: Auth0Request, res: Auth0Response, options?: LogoutOptions) => Promise<void>;

export default function logoutHandlerFactory(
  config: Config,
  getClient: ClientFactory,
  sessionCache: SessionCache<any, any>
): HandleLogout {
  return async (req, res, options = {}) => {
    let returnURL = options.returnTo || config.routes.postLogoutRedirect;
    debug('logout() with return url: %s', returnURL);

    if (url.parse(returnURL).host === null) {
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

    const client = await getClient();
    returnURL = client.endSessionUrl({
      ...options.logoutParams,
      post_logout_redirect_uri: returnURL,
      id_token_hint: idToken
    });

    debug('logging out of identity provider, redirecting to %s', returnURL);
    res.redirect(returnURL);
  };
}
