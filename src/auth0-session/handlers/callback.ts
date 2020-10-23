import { NextApiRequest, NextApiResponse } from 'next';
import urlJoin from 'url-join';
import { BadRequest } from 'http-errors';

import { Config } from '../config';
import { ClientFactory } from '../client';
import TransientCookieHandler from '../transient-handler';
import { decodeState } from '../hooks/get-login-state';
import CookieStore from '../cookie-store';
import Session from '../session';

function getRedirectUri(config: Config) {
  return urlJoin(config.baseURL, config.routes.callback);
}

export default function callbackHandler(
  config: Config,
  getClient: ClientFactory,
  sessionStore: CookieStore,
  transientCookieHandler: TransientCookieHandler
) {
  return async (req: NextApiRequest, res: NextApiResponse): Promise<void> => {
    if (!res) {
      throw new Error('Response is not available');
    }

    if (!req) {
      throw new Error('Request is not available');
    }

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
    sessionStore.set(
      req,
      res,
      new Session(
        {
          id_token: tokenSet.id_token,
          access_token: tokenSet.access_token,
          refresh_token: tokenSet.refresh_token,
          token_type: tokenSet.token_type,
          expires_at: tokenSet.expires_at
        },
        config,
        getClient
      )
    );

    res.writeHead(302, {
      Location: openidState.returnTo || config.baseURL
    });
    res.end();
  };
}
