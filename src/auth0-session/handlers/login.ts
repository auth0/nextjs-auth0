import urlJoin from 'url-join';
import { Config, LoginOptions } from '../config';
import TransientStore, { StoreOptions } from '../transient-store';
import { encodeState } from '../utils/encoding';
import createDebug from '../utils/debug';
import { Auth0Request, Auth0Response } from '../http';
import { AbstractClient } from '../client/abstract-client';

const debug = createDebug('handlers');

function getRedirectUri(config: Config): string {
  return urlJoin(config.baseURL, config.routes.callback);
}

export type HandleLogin = (req: Auth0Request, res: Auth0Response, options?: LoginOptions) => Promise<void>;

export default function loginHandlerFactory(
  config: Config,
  client: AbstractClient,
  transientHandler: TransientStore
): HandleLogin {
  return async (req, res, options = {}) => {
    const returnTo = options.returnTo || config.baseURL;

    const opts = {
      returnTo,
      getLoginState: config.getLoginState,
      ...options
    };

    // Ensure a redirect_uri, merge in configuration options, then passed-in options.
    opts.authorizationParams = {
      redirect_uri: getRedirectUri(config),
      ...config.authorizationParams,
      ...(opts.authorizationParams || {})
    };

    const transientOpts: Pick<StoreOptions, 'sameSite'> = {
      sameSite: opts.authorizationParams.response_mode === 'form_post' ? 'none' : config.session.cookie.sameSite
    };

    const stateValue = await opts.getLoginState(opts);
    if (typeof stateValue !== 'object') {
      throw new Error('Custom state value must be an object.');
    }
    stateValue.nonce = client.generateRandomNonce();
    stateValue.returnTo = stateValue.returnTo || opts.returnTo;

    const responseType = opts.authorizationParams.response_type as string;
    const usePKCE = responseType.includes('code');
    if (usePKCE) {
      debug('response_type includes code, the authorization request will use PKCE');
      stateValue.code_verifier = client.generateRandomCodeVerifier();
    }

    if (responseType !== config.authorizationParams.response_type) {
      await transientHandler.save('response_type', req, res, {
        ...transientOpts,
        value: responseType
      });
    }

    const authParams = {
      ...opts.authorizationParams,
      nonce: await transientHandler.save('nonce', req, res, { ...transientOpts, value: client.generateRandomNonce() }),
      state: await transientHandler.save('state', req, res, {
        ...transientOpts,
        value: encodeState(stateValue)
      }),
      ...(usePKCE
        ? {
            code_challenge: await client.calculateCodeChallenge(
              await transientHandler.save('code_verifier', req, res, {
                ...transientOpts,
                value: client.generateRandomCodeVerifier()
              })
            ),
            code_challenge_method: 'S256'
          }
        : undefined)
    };

    const validResponseTypes = ['id_token', 'code id_token', 'code'];
    if (!validResponseTypes.includes(authParams.response_type as string)) {
      throw new Error(`response_type should be one of ${validResponseTypes.join(', ')}`);
    }
    if (!/\bopenid\b/.test(authParams.scope as string)) {
      throw new Error('scope should contain "openid"');
    }

    if (authParams.max_age) {
      await transientHandler.save('max_age', req, res, {
        ...transientOpts,
        value: authParams.max_age.toString()
      });
    }

    const authorizationUrl = await client.authorizationUrl(authParams);
    debug('redirecting to %s', authorizationUrl);

    res.redirect(authorizationUrl);
  };
}
