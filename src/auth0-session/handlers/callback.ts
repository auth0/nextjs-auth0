import { IncomingMessage, ServerResponse } from 'http';
import urlJoin from 'url-join';
import { BadRequest } from 'http-errors';

import { TokenSet } from 'openid-client';
import { Config } from '../config';
import { ClientFactory } from '../client';
import TransientStore from '../transient-store';
import { decodeState } from '../hooks/get-login-state';
import { SessionCache } from '../session-cache';

function getRedirectUri(config: Config): string {
  return urlJoin(config.baseURL, config.routes.callback);
}

export type CallbackOptions = {
  afterCallback?: (
    req: IncomingMessage,
    res: ServerResponse,
    tokenSet: TokenSet,
    state: Record<string, any>
  ) => Promise<TokenSet> | TokenSet;
};

export default function callbackHandler(
  config: Config,
  getClient: ClientFactory,
  sessionCache: SessionCache,
  transientCookieHandler: TransientStore
) {
  return async (req: IncomingMessage, res: ServerResponse, options?: CallbackOptions): Promise<void> => {
    const client = await getClient();

    const redirectUri = getRedirectUri(config);

    let expectedState;
    let tokenSet;
    try {
      const callbackParams = client.callbackParams(req);
      expectedState = transientCookieHandler.read('state', req, res);
      const max_age = transientCookieHandler.read('max_age', req, res);
      const code_verifier = transientCookieHandler.read('code_verifier', req, res);
      const nonce = transientCookieHandler.read('nonce', req, res);

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
    tokenSet = new TokenSet({
      access_token: tokenSet.access_token,
      token_type: tokenSet.token_type,
      id_token: tokenSet.id_token,
      refresh_token: tokenSet.refresh_token,
      expires_at: tokenSet.expires_at,
      session_state: tokenSet.session_state,
      scope: tokenSet.scope
    });

    if (options?.afterCallback) {
      tokenSet = await options.afterCallback(req, res, tokenSet, openidState);
    }

    sessionCache.create(req, res, tokenSet);

    res.writeHead(302, {
      Location: openidState.returnTo || config.baseURL
    });
    res.end();
  };
}
