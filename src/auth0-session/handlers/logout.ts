import { IncomingMessage, ServerResponse } from 'http';
import url from 'url';
import urlJoin from 'url-join';
import createDebug from '../utils/debug';
import { Config } from '../config';
import { ClientFactory } from '../client';
import { SessionCache } from '../session-cache';

const debug = createDebug('logout');

export interface LogoutOptions {
  returnTo?: string;
}

export default function logoutHandler(config: Config, getClient: ClientFactory, sessionCache: SessionCache) {
  return async (req: IncomingMessage, res: ServerResponse, options: LogoutOptions = {}): Promise<void> => {
    let returnURL = options.returnTo || config.routes.postLogoutRedirect;
    debug('logout() with return url: %s', returnURL);

    if (url.parse(returnURL).host === null) {
      returnURL = urlJoin(config.baseURL, returnURL);
    }

    if (!sessionCache.isAuthenticated(req)) {
      debug('end-user already logged out, redirecting to %s', returnURL);
      res.writeHead(302, {
        Location: returnURL
      });
      res.end();
      return;
    }

    sessionCache.delete(req);

    if (!config.idpLogout) {
      debug('performing a local only logout, redirecting to %s', returnURL);
      res.writeHead(302, {
        Location: returnURL
      });
      res.end();
      return;
    }

    const client = await getClient();
    returnURL = client.endSessionUrl({
      post_logout_redirect_uri: returnURL,
      id_token_hint: sessionCache.getIdToken(req)
    });

    debug('logging out of identity provider, redirecting to %s', returnURL);
    res.writeHead(302, {
      Location: returnURL
    });
    res.end();
  };
}
