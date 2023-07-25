import urlJoin from 'url-join';
import { AuthorizationParameters, Config } from '../config';
import TransientStore from '../transient-store';
import { decodeState } from '../utils/encoding';
import { SessionCache } from '../session-cache';
import { MissingStateCookieError, MissingStateParamError } from '../utils/errors';
import { Auth0Request, Auth0Response } from '../http';
import { AbstractClient } from '../client/abstract-client';

function getRedirectUri(config: Config): string {
  return urlJoin(config.baseURL, config.routes.callback);
}

export type AfterCallback = (session: any, state?: Record<string, any>) => Promise<any> | any | undefined;

export type CallbackOptions = {
  afterCallback?: AfterCallback;

  redirectUri?: string;

  authorizationParams?: Partial<AuthorizationParameters>;
};

export type HandleCallback = (req: Auth0Request, res: Auth0Response, options?: CallbackOptions) => Promise<void>;

export default function callbackHandlerFactory(
  config: Config,
  client: AbstractClient,
  sessionCache: SessionCache,
  transientCookieHandler: TransientStore
): HandleCallback {
  return async (req, res, options) => {
    const redirectUri = options?.redirectUri || getRedirectUri(config);

    let tokenResponse;

    const expectedState = await transientCookieHandler.read('state', req, res);
    if (!expectedState) {
      throw new MissingStateCookieError();
    }

    let callbackParams: URLSearchParams;
    try {
      callbackParams = await client.callbackParams(req, expectedState);
    } catch (err) {
      err.status = 400;
      err.statusCode = 400;
      err.openIdState = decodeState(expectedState);
      throw err;
    }

    if (!callbackParams.get('state')) {
      throw new MissingStateParamError();
    }
    const max_age = await transientCookieHandler.read('max_age', req, res);
    const code_verifier = await transientCookieHandler.read('code_verifier', req, res);
    const nonce = await transientCookieHandler.read('nonce', req, res);
    const response_type =
      (await transientCookieHandler.read('response_type', req, res)) || config.authorizationParams.response_type;

    try {
      tokenResponse = await client.callback(
        redirectUri,
        callbackParams,
        {
          max_age: max_age !== undefined ? +max_age : undefined,
          code_verifier,
          nonce,
          state: expectedState,
          response_type
        },
        { exchangeBody: options?.authorizationParams }
      );
    } catch (err) {
      err.status = 400;
      err.statusCode = 400;
      err.openIdState = decodeState(expectedState);
      throw err;
    }

    const openidState: { returnTo?: string } = decodeState(expectedState as string)!;
    let session = sessionCache.fromTokenEndpointResponse(tokenResponse);

    if (options?.afterCallback) {
      session = await options.afterCallback(session, openidState);
    }

    if (session) {
      await sessionCache.create(req.req, res.res, session);
    }

    res.redirect(openidState.returnTo || config.baseURL);
  };
}
