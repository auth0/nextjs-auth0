import { NextApiRequest, NextApiResponse } from 'next';
import url from 'url';
import urlJoin from 'url-join';

import createDebug from '../debug';
import { Config } from '../config';
import { ClientFactory } from '../client';
import CookieStore from '../cookie-store';

const debug = createDebug('logout');

export interface LogoutOptions {
  returnTo?: string;
}

export default function logoutHandler(config: Config, getClient: ClientFactory, sessionStore: CookieStore) {
  return async (req: NextApiRequest, res: NextApiResponse, options: LogoutOptions = {}): Promise<void> => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    const session = sessionStore.get(req, res);

    let returnURL = options.returnTo || config.routes.postLogoutRedirect;
    debug('logout() with return url: %s', returnURL);

    if (url.parse(returnURL).host === null) {
      returnURL = urlJoin(config.baseURL, returnURL);
    }

    if (!session?.isAuthenticated()) {
      debug('end-user already logged out, redirecting to %s', returnURL);
      res.writeHead(302, {
        Location: returnURL
      });
      res.end();
      return;
    }

    sessionStore.delete(req, res);

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
      id_token_hint: session?.idToken
    });

    debug('logging out of identity provider, redirecting to %s', returnURL);
    res.writeHead(302, {
      Location: returnURL
    });
    res.end();
  };
}
