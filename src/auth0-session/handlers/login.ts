import { NextApiRequest, NextApiResponse } from 'next';
import urlJoin from 'url-join';
import { strict as assert } from 'assert';

import isSafeRedirect from '../../utils/url-helpers';

import { Config, LoginOptions } from '../config';
import { StoreOptions } from '../transient-handler';
import { encodeState } from '../hooks/get-login-state';
import { ClientFactory } from '../client';
import createDebug from '../debug';
import TransientCookieHandler from '../transient-handler';

const debug = createDebug('handlers');

function getRedirectUri(config: Config) {
  return urlJoin(config.baseURL, config.routes.callback);
}

export default function loginHandler(
  config: Config,
  getClient: ClientFactory,
  transientHandler: TransientCookieHandler
) {
  return async (req: NextApiRequest, res: NextApiResponse, options: LoginOptions = {}): Promise<void> => {
    if (!req) {
      throw new Error('Request is not available');
    }

    if (!res) {
      throw new Error('Response is not available');
    }

    if (req.query.redirectTo) {
      if (typeof req.query.redirectTo !== 'string') {
        throw new Error('Invalid value provided for redirectTo, must be a string');
      }

      if (!isSafeRedirect(req.query.redirectTo)) {
        throw new Error('Invalid value provided for redirectTo, must be a relative url');
      }
    }

    const client = await getClient();

    let returnTo = options.returnTo || config.baseURL;

    options = {
      returnTo,
      ...options
    };

    // Ensure a redirect_uri, merge in configuration options, then passed-in options.
    options.authorizationParams = {
      redirect_uri: getRedirectUri(config),
      ...config.authorizationParams,
      ...(options.authorizationParams || {})
    };

    const transientOpts: StoreOptions = {
      sameSite: options.authorizationParams.response_mode === 'form_post' ? 'none' : 'lax'
    };

    const stateValue = await config.getLoginState(req, options);
    if (typeof stateValue !== 'object') {
      throw new Error('Custom state value must be an object.');
    }
    stateValue.nonce = transientHandler.generateNonce();

    const usePKCE = options.authorizationParams.response_type?.includes('code');
    if (usePKCE) {
      debug('response_type includes code, the authorization request will use PKCE');
      stateValue.code_verifier = transientHandler.generateCodeVerifier();
    }

    const authParams = {
      ...options.authorizationParams,
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
