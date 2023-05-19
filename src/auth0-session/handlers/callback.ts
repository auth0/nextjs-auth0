import urlJoin from 'url-join';
import createHttpError from 'http-errors';
import { errors } from 'openid-client';
import { AuthorizationParameters, Config } from '../config';
import { ClientFactory } from '../client';
import TransientStore from '../transient-store';
import { decodeState } from '../utils/encoding';
import { SessionCache } from '../session-cache';
import {
  ApplicationError,
  EscapedError,
  IdentityProviderError,
  MissingStateCookieError,
  MissingStateParamError
} from '../utils/errors';
import { AbstractRequest, AbstractResponse } from '../http';
import { IncomingMessage } from 'http';

function getRedirectUri(config: Config): string {
  return urlJoin(config.baseURL, config.routes.callback);
}

export type AfterCallback = (session: any, state?: Record<string, any>) => Promise<any> | any | undefined;

export type CallbackOptions = {
  afterCallback?: AfterCallback;

  redirectUri?: string;

  authorizationParams?: Partial<AuthorizationParameters>;
};

type ValidState = { [key: string]: any; returnTo?: string };

export type HandleCallback = (req: AbstractRequest, res: AbstractResponse, options?: CallbackOptions) => Promise<void>;

export default function callbackHandlerFactory(
  config: Config,
  getClient: ClientFactory,
  sessionCache: SessionCache<any, any>,
  transientCookieHandler: TransientStore
): HandleCallback {
  return async (req, res, options) => {
    const client = await getClient();
    const redirectUri = options?.redirectUri || getRedirectUri(config);

    let tokenSet;

    const callbackParams = client.callbackParams({
      method: req.getMethod(),
      url: req.getUrl(),
      body: await req.getBody()
    } as unknown as IncomingMessage);

    if (!callbackParams.state) {
      throw createHttpError(404, new MissingStateParamError());
    }

    const expectedState = await transientCookieHandler.read('state', req, res);

    if (!expectedState) {
      throw createHttpError(400, new MissingStateCookieError());
    }

    const max_age = await transientCookieHandler.read('max_age', req, res);
    const code_verifier = await transientCookieHandler.read('code_verifier', req, res);
    const nonce = await transientCookieHandler.read('nonce', req, res);
    const response_type =
      (await transientCookieHandler.read('response_type', req, res)) || config.authorizationParams.response_type;

    try {
      tokenSet = await client.callback(
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
      if (err instanceof errors.OPError) {
        err = new IdentityProviderError(err);
      } else if (err instanceof errors.RPError) {
        err = new ApplicationError(err);
        /* c8 ignore next 3 */
      } else {
        err = new EscapedError(err.message);
      }
      throw createHttpError(400, err, { openIdState: decodeState(expectedState) });
    }

    const openidState: { returnTo?: string } = decodeState(expectedState as string) as ValidState;
    let session = sessionCache.fromTokenSet(tokenSet);

    if (options?.afterCallback) {
      session = await options.afterCallback(session, openidState);
    }

    if (session) {
      await sessionCache.create(req.req, res.res, session);
    }

    res.redirect(openidState.returnTo || config.baseURL);
  };
}
