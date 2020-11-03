import { IncomingMessage, ServerResponse } from 'http';
import urlJoin from 'url-join';
import { strict as assert } from 'assert';
import { Config, LoginOptions } from '../config';
import TransientCookieHandler, { StoreOptions } from '../transient-handler';
import { encodeState } from '../hooks/get-login-state';
import { ClientFactory } from '../client';
import createDebug from '../utils/debug';

const debug = createDebug('handlers');

function getRedirectUri(config: Config): string {
  return urlJoin(config.baseURL, config.routes.callback);
}

export default function loginHandler(
  config: Config,
  getClient: ClientFactory,
  transientHandler: TransientCookieHandler
) {
  return async (req: IncomingMessage, res: ServerResponse, options: LoginOptions = {}): Promise<void> => {
    const client = await getClient();

    const returnTo = options.returnTo || config.baseURL;

    const opts = {
      returnTo,
      ...options
    };

    // Ensure a redirect_uri, merge in configuration options, then passed-in options.
    opts.authorizationParams = {
      redirect_uri: getRedirectUri(config),
      ...config.authorizationParams,
      ...(opts.authorizationParams || {})
    };

    const transientOpts: StoreOptions = {
      sameSite: opts.authorizationParams.response_mode === 'form_post' ? 'none' : 'lax'
    };

    const stateValue = await config.getLoginState(req, opts);
    if (typeof stateValue !== 'object') {
      throw new Error('Custom state value must be an object.');
    }
    stateValue.nonce = transientHandler.generateNonce();

    const usePKCE = opts.authorizationParams.response_type?.includes('code');
    if (usePKCE) {
      debug('response_type includes code, the authorization request will use PKCE');
      stateValue.code_verifier = transientHandler.generateCodeVerifier();
    }

    const authParams = {
      ...opts.authorizationParams,
      nonce: transientHandler.store('nonce', req, res, transientOpts),
      state: transientHandler.store('state', req, res, {
        ...transientOpts,
        value: encodeState(stateValue)
      }),
      ...(usePKCE
        ? {
            code_challenge: transientHandler.calculateCodeChallenge(
              transientHandler.store('code_verifier', req, res, transientOpts)
            ),
            code_challenge_method: 'S256'
          }
        : undefined)
    };

    const validResponseTypes = ['id_token', 'code id_token', 'code'];
    assert(
      validResponseTypes.includes(authParams.response_type),
      `response_type should be one of ${validResponseTypes.join(', ')}`
    );
    assert(/\bopenid\b/.test(authParams.scope), 'scope should contain "openid"');

    if (authParams.max_age) {
      transientHandler.store('max_age', req, res, {
        ...transientOpts,
        value: authParams.max_age.toString()
      });
    }

    const authorizationUrl = client.authorizationUrl(authParams);
    debug('redirecting to %s', authorizationUrl);

    res.writeHead(302, {
      Location: authorizationUrl
    });
    res.end();
  };
}
