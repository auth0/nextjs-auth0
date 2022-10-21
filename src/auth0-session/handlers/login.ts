import { IncomingMessage, ServerResponse } from 'http';
import urlJoin from 'url-join';
import { strict as assert } from 'assert';
import { Config, LoginOptions } from '../config';
import TransientStore, { StoreOptions } from '../transient-store';
import { encodeState } from '../utils/encoding';
import { ClientFactory } from '../client';
import createDebug from '../utils/debug';
import { htmlSafe } from '../utils/errors';

const debug = createDebug('handlers');

function getRedirectUri(config: Config): string {
  return urlJoin(config.baseURL, config.routes.callback);
}

export type HandleLogin = (req: IncomingMessage, res: ServerResponse, options?: LoginOptions) => Promise<void>;

export default function loginHandlerFactory(
  config: Config,
  getClient: ClientFactory,
  transientHandler: TransientStore
): HandleLogin {
  return async (req, res, options = {}) => {
    const client = await getClient();

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

    const transientOpts: StoreOptions = {
      sameSite: opts.authorizationParams.response_mode === 'form_post' ? 'none' : config.session.cookie.sameSite
    };

    const stateValue = await opts.getLoginState(req as any, opts);
    if (typeof stateValue !== 'object') {
      throw new Error('Custom state value must be an object.');
    }
    stateValue.nonce = transientHandler.generateNonce();
    stateValue.returnTo = stateValue.returnTo || opts.returnTo;

    const responseType = opts.authorizationParams.response_type as string;
    const usePKCE = responseType.includes('code');
    if (usePKCE) {
      debug('response_type includes code, the authorization request will use PKCE');
      stateValue.code_verifier = transientHandler.generateCodeVerifier();
    }

    if (responseType !== config.authorizationParams.response_type) {
      await transientHandler.save('response_type', req, res, {
        ...transientOpts,
        value: responseType
      });
    }

    const authParams = {
      ...opts.authorizationParams,
      nonce: await transientHandler.save('nonce', req, res, transientOpts),
      state: await transientHandler.save('state', req, res, {
        ...transientOpts,
        value: encodeState(stateValue)
      }),
      ...(usePKCE
        ? {
            code_challenge: transientHandler.calculateCodeChallenge(
              await transientHandler.save('code_verifier', req, res, transientOpts)
            ),
            code_challenge_method: 'S256'
          }
        : undefined)
    };

    const validResponseTypes = ['id_token', 'code id_token', 'code'];
    assert(
      validResponseTypes.includes(authParams.response_type as string),
      `response_type should be one of ${validResponseTypes.join(', ')}`
    );
    assert(/\bopenid\b/.test(authParams.scope as string), 'scope should contain "openid"');

    if (authParams.max_age) {
      await transientHandler.save('max_age', req, res, {
        ...transientOpts,
        value: authParams.max_age.toString()
      });
    }

    const authorizationUrl = client.authorizationUrl(authParams);
    debug('redirecting to %s', authorizationUrl);

    res.writeHead(302, {
      Location: authorizationUrl
    });
    res.end(htmlSafe(authorizationUrl));
  };
}
