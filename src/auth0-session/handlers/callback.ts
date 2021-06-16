import { IncomingMessage, ServerResponse } from 'http';
import urlJoin from 'url-join';
import { BadRequest } from 'http-errors';
import { Config } from '../config';
import { ClientFactory } from '../client';
import TransientStore from '../transient-store';
import { decodeState } from '../hooks/get-login-state';
import { SessionCache } from '../session-cache';

function getRedirectUri(config: Config): string {
  return urlJoin(config.baseURL, config.routes.callback);
}

// eslint-disable-next-line max-len
// Basic escaping for putting untrusted data directly into the HTML body, per: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-1-html-encode-before-inserting-untrusted-data-into-html-element-content
function htmlSafe(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export type AfterCallback = (req: any, res: any, session: any, state: Record<string, any>) => Promise<any> | any;

export type CallbackOptions = {
  afterCallback?: AfterCallback;

  redirectUri?: string;
};

export type HandleCallback = (req: IncomingMessage, res: ServerResponse, options?: CallbackOptions) => Promise<void>;

export default function callbackHandlerFactory(
  config: Config,
  getClient: ClientFactory,
  sessionCache: SessionCache,
  transientCookieHandler: TransientStore
): HandleCallback {
  return async (req, res, options) => {
    const client = await getClient();
    const redirectUri = options?.redirectUri || getRedirectUri(config);

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
      // The error message can come from the route's query parameters, so do some basic escaping.
      throw new BadRequest(htmlSafe(err.message));
    }

    const openidState: { returnTo?: string } = decodeState(expectedState as string);
    let session = sessionCache.fromTokenSet(tokenSet);

    if (options?.afterCallback) {
      session = await options.afterCallback(req as any, res as any, session, openidState);
    }

    sessionCache.create(req, res, session);

    res.writeHead(302, {
      Location: openidState.returnTo || config.baseURL
    });
    res.end();
  };
}
