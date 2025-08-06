import { IncomingMessage, ServerResponse } from 'http';
import url from 'url';
import urlJoin from 'url-join';
import createDebug from '../utils/debug';
import { Config, LogoutOptions } from '../config';
import { ClientFactory } from '../client';
import { SessionCache } from '../session-cache';
import { htmlSafe } from '../utils/errors';

const debug = createDebug('logout');

export type HandleLogout = (req: IncomingMessage, res: ServerResponse, options?: LogoutOptions) => Promise<void>;

/**
 * Remove a cookie by creating a matching removal header with all possible attributes
 */
function removeCookie(res: ServerResponse, cookieName: string, cookieConfig: any = {}) {
  let cookieString = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;

  // Add path (default to '/')
  const path = cookieConfig.path || '/';
  cookieString += `; Path=${path}`;

  // Add domain if specified
  if (cookieConfig.domain) {
    cookieString += `; Domain=${cookieConfig.domain}`;
  }

  // Add security attributes to match original cookie
  if (cookieConfig.secure !== false) {
    cookieString += '; Secure';
  }

  if (cookieConfig.httpOnly !== false) {
    cookieString += '; HttpOnly';
  }

  if (cookieConfig.sameSite) {
    cookieString += `; SameSite=${cookieConfig.sameSite}`;
  }

  if (cookieConfig.partitioned) {
    cookieString += '; Partitioned';
  }

  // Add to existing Set-Cookie headers
  const existingCookies = res.getHeader('Set-Cookie') || [];
  const cookieArray = Array.isArray(existingCookies) ? existingCookies : [existingCookies as string];
  cookieArray.push(cookieString);

  res.setHeader('Set-Cookie', cookieArray);
}

export default function logoutHandlerFactory(
  config: Config,
  getClient: ClientFactory,
  sessionCache: SessionCache
): HandleLogout {
  return async (req, res, options = {}) => {
    let returnURL = options.returnTo || config.routes.postLogoutRedirect;
    debug('logout() with return url: %s', returnURL);

    if (url.parse(returnURL).host === null) {
      returnURL = urlJoin(config.baseURL, returnURL);
    }

    const isAuthenticated = await sessionCache.isAuthenticated(req, res);
    if (!isAuthenticated) {
      debug('end-user already logged out, redirecting to %s', returnURL);
      res.writeHead(302, {
        Location: returnURL
      });
      res.end(htmlSafe(returnURL));
      return;
    }

    const idToken = await sessionCache.getIdToken(req, res);
    await sessionCache.delete(req, res);

    // Remove the session cookie with matching attributes
    const cookieName = config.session?.name || 'appSession';

    removeCookie(res, cookieName, config.session?.cookie);

    // Also remove with partitioned flag to ensure cleanup regardless of original cookie config
    const cookieConfigWithPartitioned = {
      ...config.session?.cookie,
      partitioned: true
    };
    removeCookie(res, cookieName, cookieConfigWithPartitioned);

    if (!config.idpLogout) {
      debug('performing a local only logout, redirecting to %s', returnURL);
      res.writeHead(302, {
        Location: returnURL
      });
      res.end(htmlSafe(returnURL));
      return;
    }

    const client = await getClient();
    returnURL = client.endSessionUrl({
      ...options.logoutParams,
      post_logout_redirect_uri: returnURL,
      id_token_hint: idToken
    });

    debug('logging out of identity provider, redirecting to %s', returnURL);
    res.writeHead(302, {
      Location: returnURL
    });
    res.end(htmlSafe(returnURL));
  };
}
