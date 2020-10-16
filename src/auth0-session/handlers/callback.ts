import { IncomingMessage, ServerResponse } from 'http';
import urlJoin from 'url-join';
import { BadRequest } from 'http-errors';

import { TokenSet } from 'openid-client';
import { Config } from '../config';
import { ClientFactory } from '../client';
import TransientCookieHandler from '../transient-handler';
import { decodeState } from '../hooks/get-login-state';
import { SessionCache } from '../session-cache';

function getRedirectUri(config: Config) {
  return urlJoin(config.baseURL, config.routes.callback);
}

export default function callbackHandler(
  config: Config,
  getClient: ClientFactory,
  sessionCache: SessionCache,
  transientCookieHandler: TransientCookieHandler
) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const client = await getClient();
    if (!client) {
      return;
    }

    const redirectUri = getRedirectUri(config);

    let expectedState;
    let tokenSet;
    try {
      const callbackParams = client.callbackParams(req);
      expectedState = transientCookieHandler.getOnce('state', req, res);
      let max_age = transientCookieHandler.getOnce('max_age', req, res);
      const code_verifier = transientCookieHandler.getOnce('code_verifier', req, res);
      const nonce = transientCookieHandler.getOnce('nonce', req, res);

      tokenSet = await client.callback(redirectUri, callbackParams, {
        max_age: max_age !== undefined ? +max_age : undefined,
        code_verifier,
        nonce,
        state: expectedState
      });
    } catch (err) {
      throw new BadRequest(err.message);
    }

    const openidState: { returnTo?: string } = decodeState(expectedState as string);

    // intentional clone of the properties on tokenSet
    sessionCache.create(
      req,
      new TokenSet({
        access_token: tokenSet.access_token,
        token_type: tokenSet.token_type,
        id_token: tokenSet.id_token,
        refresh_token: tokenSet.refresh_token,
        expires_at: tokenSet.expires_at,
        session_state: tokenSet.session_state,
        scope: tokenSet.scope
      })
    );

    res.writeHead(302, {
      Location: openidState.returnTo || config.baseURL
    });
    res.end();
  };
}
