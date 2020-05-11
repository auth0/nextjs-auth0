import { IncomingMessage, ServerResponse } from 'http';

import IAuth0Settings from '../settings';
import { setCookies } from '../utils/cookies';
import { IOidcClientFactory } from '../utils/oidc-client';
import CookieSessionStoreSettings from '../session/cookie-store/settings';
import { ISessionStore } from '../session/store';

function createLogoutUrl(settings: IAuth0Settings): string {
  return (
    `https://${settings.domain}/v2/logout?` +
    `client_id=${settings.clientId}` +
    `&returnTo=${encodeURIComponent(settings.postLogoutRedirectUri)}`
  );
}

export default function logoutHandler(
  settings: IAuth0Settings,
  sessionSettings: CookieSessionStoreSettings,
  clientProvider: IOidcClientFactory,
  store: ISessionStore
) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    const session = await store.read(req);
    let endSessionUrl;

    try {
      const client = await clientProvider();
      endSessionUrl = client.endSessionUrl({
        id_token_hint: session ? session.idToken : undefined,
        post_logout_redirect_uri: encodeURIComponent(settings.postLogoutRedirectUri)
      });
    } catch (err) {
      if (/end_session_endpoint must be configured/.exec(err)) {
        // Use default url if end_session_endpoint is not configured
        endSessionUrl = createLogoutUrl(settings);
      } else {
        throw err;
      }
    }

    // Remove the cookies
    setCookies(req, res, [
      {
        name: 'a0:state',
        value: '',
        maxAge: -1
      },
      {
        name: sessionSettings.cookieName,
        value: '',
        maxAge: -1,
        path: sessionSettings.cookiePath,
        domain: sessionSettings.cookieDomain
      }
    ]);

    // Redirect to the logout endpoint.
    res.writeHead(302, {
      Location: endSessionUrl
    });
    res.end();
  };
}
