import urlJoin from 'url-join';
import { AuthorizationParameters, GetConfig, Config } from '../config';
import TransientStore from '../transient-store';
import { decodeState } from '../utils/encoding';
import { SessionCache } from '../session-cache';
import { MalformedStateCookieError, MissingStateCookieError, MissingStateParamError } from '../utils/errors';
import { Auth0Request, Auth0Response } from '../http';
import { GetClient } from '../client/abstract-client';
import type { AuthVerification } from './login';

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
  getConfig: GetConfig,
  getClient: GetClient,
  sessionCache: SessionCache,
  transientCookieHandler: TransientStore
): HandleCallback {
  const getConfigFn = typeof getConfig === 'function' ? getConfig : () => getConfig;
  return async (req, res, options) => {
    const config = await getConfigFn(req);
    const client = await getClient(config);
    const redirectUri = options?.redirectUri || getRedirectUri(config);

    let tokenResponse;

    let authVerification: AuthVerification;
    const cookie = await transientCookieHandler.read(config.transactionCookie.name, req, res);

    if (!cookie) {
      throw new MissingStateCookieError();
    }

    try {
      authVerification = JSON.parse(cookie);
    } catch (_) {
      throw new MalformedStateCookieError();
    }

    const {
      max_age,
      code_verifier,
      nonce,
      state: expectedState,
      response_type = config.authorizationParams.response_type
    } = authVerification;

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
    let session = await sessionCache.fromTokenEndpointResponse(req, res, tokenResponse);

    if (options?.afterCallback) {
      session = await options.afterCallback(session, openidState);
    }

    if (session) {
      await sessionCache.create(req.req, res.res, session);
    }

    res.redirect(openidState.returnTo || config.baseURL);
  };
}
