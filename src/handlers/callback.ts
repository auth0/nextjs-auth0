import { IncomingMessage, ServerResponse } from 'http';

import IAuth0Settings from '../settings';
import { ISession } from '../session/session';
import { parseCookies } from '../utils/cookies';
import { ISessionStore } from '../session/store';
import { IOidcClientFactory } from '../utils/oidc-client';
import { CallbackOptions } from './callback-options';

export default function callbackHandler(
  settings: IAuth0Settings,
  clientProvider: IOidcClientFactory,
  sessionStore: ISessionStore
) {
  return async (req: IncomingMessage, res: ServerResponse, options?: CallbackOptions): Promise<void> => {
    if (!res) {
      throw new Error('Response is not available');
    }

    if (!req) {
      throw new Error('Request is not available');
    }

    // Parse the cookies.
    const cookies = parseCookies(req);

    // Require that we have a state.
    const state = cookies['a0:state'];
    if (!state) {
      throw new Error('Invalid request, an initial state could not be found');
    }

    // Execute the code exchange
    const client = await clientProvider();
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(settings.redirectUri, params, {
      state
    });

    // Get the claims without any OIDC specific claim.
    const claims = tokenSet.claims();
    if (claims.aud) {
      delete claims.aud;
    }

    if (claims.exp) {
      delete claims.exp;
    }

    if (claims.iat) {
      delete claims.iat;
    }

    if (claims.iss) {
      delete claims.iss;
    }

    // Create the session.
    const session: ISession = {
      user: {
        ...claims
      },
      idToken: tokenSet.id_token,
      accessToken: tokenSet.access_token,
      createdAt: Date.now()
    };

    // Create the session.
    await sessionStore.save(req, res, session);

    // Redirect to the homepage.
    const redirectTo = (options && options.redirectTo) || '/';
    res.writeHead(302, {
      Location: redirectTo
    });
    res.end();
  };
}
