const cb = require('cb');
const url = require('url');
const urlJoin = require('url-join');
const { TokenSet } = require('openid-client');
const clone = require('clone');
const createError = require('http-errors');
const { strict: assert } = require('assert');

const debug = require('./debug')('context');
const { get: getClient } = require('./client');
const { encodeState, decodeState } = require('./hooks/get-login-state');
// const { cancelSilentLogin } = require('../middleware/attemptSilentLogin');
const TransientCookieHandler = require('./transient-handler');
const weakRef = require('./weak-cache');

function isExpired() {
  return tokenSet.call(this).expired();
}

function getRedirectUri(config) {
  return urlJoin(config.baseURL, config.routes.callback);
}

async function refresh() {
  let { config, req } = weakRef(this);
  const client = await getClient(config);
  const oldTokenSet = tokenSet.call(this);
  const newTokenSet = await client.refresh(oldTokenSet);

  // Update the session
  const session = req[config.session.name];
  Object.assign(session, {
    id_token: newTokenSet.id_token,
    access_token: newTokenSet.access_token,
    // If no new refresh token assume the current refresh token is valid.
    refresh_token: newTokenSet.refresh_token || oldTokenSet.refresh_token,
    token_type: newTokenSet.token_type,
    expires_at: newTokenSet.expires_at,
  });

  // Delete the old token set
  const cachedTokenSet = weakRef(session);
  delete cachedTokenSet.value;

  return this.accessToken;
}

function tokenSet() {
  const contextCache = weakRef(this);
  const session = contextCache.req[contextCache.config.session.name];

  if (!session || !('id_token' in session)) {
    return undefined;
  }

  const cachedTokenSet = weakRef(session);

  if (!('value' in cachedTokenSet)) {
    const {
      id_token,
      access_token,
      refresh_token,
      token_type,
      expires_at,
    } = session;
    cachedTokenSet.value = new TokenSet({
      id_token,
      access_token,
      refresh_token,
      token_type,
      expires_at,
    });
  }

  return cachedTokenSet.value;
}

class RequestContext {
  constructor(config, req) {
    Object.assign(weakRef(this), { config, req });
  }

  isAuthenticated() {
    return !!this.idTokenClaims;
  }

  get idToken() {
    try {
      return tokenSet.call(this).id_token;
    } catch (err) {
      return undefined;
    }
  }

  get refreshToken() {
    try {
      return tokenSet.call(this).refresh_token;
    } catch (err) {
      return undefined;
    }
  }

  get accessToken() {
    try {
      const { access_token, token_type, expires_in } = tokenSet.call(this);

      if (!access_token || !token_type || typeof expires_in !== 'number') {
        return undefined;
      }

      return {
        access_token,
        token_type,
        expires_in,
        isExpired: isExpired.bind(this),
        refresh: refresh.bind(this),
      };
    } catch (err) {
      return undefined;
    }
  }

  get idTokenClaims() {
    try {
      return clone(tokenSet.call(this).claims());
    } catch (err) {
      return undefined;
    }
  }

  get user() {
    try {
      const {
        config: { identityClaimFilter },
      } = weakRef(this);
      const { idTokenClaims } = this;
      const user = clone(idTokenClaims);
      identityClaimFilter.forEach((claim) => {
        delete user[claim];
      });
      return user;
    } catch (err) {
      return undefined;
    }
  }

  async fetchUserInfo() {
    const { config } = weakRef(this);

    const client = await getClient(config);
    return client.userinfo(tokenSet.call(this));
  }
}

class ResponseContext {
  constructor(config, req, res, transient) {
    Object.assign(weakRef(this), { config, req, res, transient });
  }

  get errorOnRequiredAuth() {
    return weakRef(this).config.errorOnRequiredAuth;
  }

  silentLogin(options) {
    return this.login({
      ...options,
      prompt: 'none',
    });
  }

  async login(options = {}) {
    let { config, req, res, transient } = weakRef(this);
    const client = await getClient(config);

    // Set default returnTo value, allow passed-in options to override or use originalUrl on GET
    let returnTo = config.baseURL;
    if (options.returnTo) {
      returnTo = options.returnTo;
      debug('login() called with returnTo: %s', returnTo);
    } else if (req.method === 'GET' && req.originalUrl) {
      returnTo = req.originalUrl;
      debug('login() without returnTo, using: %s', returnTo);
    }

    options = {
      authorizationParams: {},
      returnTo,
      ...options,
    };

    // Ensure a redirect_uri, merge in configuration options, then passed-in options.
    options.authorizationParams = {
      redirect_uri: getRedirectUri(config),
      ...config.authorizationParams,
      ...options.authorizationParams,
    };

    const transientOpts = {
      sameSite:
        options.authorizationParams.response_mode === 'form_post'
          ? 'None'
          : 'Lax',
    };

    const stateValue = await config.getLoginState(req, options);
    if (typeof stateValue !== 'object') {
      throw new Error('Custom state value must be an object.');
    }
    stateValue.nonce = transient.generateNonce();

    const usePKCE = options.authorizationParams.response_type.includes('code');
    if (usePKCE) {
      debug(
        'response_type includes code, the authorization request will use PKCE'
      );
      stateValue.code_verifier = transient.generateCodeVerifier();
    }

    const authParams = {
      ...options.authorizationParams,
      nonce: transient.store('nonce', req, res, transientOpts),
      state: transient.store('state', req, res, {
        ...transientOpts,
        value: encodeState(stateValue),
      }),
      ...(usePKCE
        ? {
            code_challenge: transient.calculateCodeChallenge(
              transient.store('code_verifier', req, res, transientOpts)
            ),
            code_challenge_method: 'S256',
          }
        : undefined),
    };

    const validResponseTypes = ['id_token', 'code id_token', 'code'];
    assert(
      validResponseTypes.includes(authParams.response_type),
      `response_type should be one of ${validResponseTypes.join(', ')}`
    );
    assert(
      /\bopenid\b/.test(authParams.scope),
      'scope should contain "openid"'
    );

    // TODO: hook here

    if (authParams.max_age) {
      transient.store('max_age', req, res, {
        ...transientOpts,
        value: authParams.max_age,
      });
    }

    const authorizationUrl = client.authorizationUrl(authParams);
    debug('redirecting to %s', authorizationUrl);
    res.redirect(authorizationUrl);
  }

  async callback() {
    let { config, req, res, transient } = weakRef(this);

    const client = await getClient(config);

    if (!client) {
      return;
    }

    const redirectUri = getRedirectUri(config);

    let expectedState;
    let tokenSet;
    try {
      const callbackParams = client.callbackParams(req);
      expectedState = transient.getOnce('state', req, res);
      const max_age = parseInt(
        transient.getOnce('max_age', req, res),
        10
      );
      const code_verifier = transient.getOnce('code_verifier', req, res);
      const nonce = transient.getOnce('nonce', req, res);

      tokenSet = await client.callback(redirectUri, callbackParams, {
        max_age,
        code_verifier,
        nonce,
        state: expectedState,
      });
    } catch (err) {
      throw createError.BadRequest(err.message);
    }

    const openidState = decodeState(expectedState);

    // intentional clone of the properties on tokenSet
    Object.assign(req[config.session.name], {
      id_token: tokenSet.id_token,
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token,
      token_type: tokenSet.token_type,
      expires_at: tokenSet.expires_at,
    });

    // attemptSilentLogin.resumeSilentLogin(req, res);

    res.redirect(openidState.returnTo || config.baseURL);
  }

  async logout(params = {}) {
    let { config, req, res } = weakRef(this);
    const client = await getClient(config);

    let returnURL = params.returnTo || config.routes.postLogoutRedirect;
    debug('logout() with return url: %s', returnURL);

    if (url.parse(returnURL).host === null) {
      returnURL = urlJoin(config.baseURL, returnURL);
    }

    // cancelSilentLogin(req, res);

    // @TODO
    if (!req.oidc.isAuthenticated()) {
      debug('end-user already logged out, redirecting to %s', returnURL);
      return res.redirect(returnURL);
    }

    req[config.session.name] = undefined;

    if (!config.idpLogout) {
      debug('performing a local only logout, redirecting to %s', returnURL);
      return res.redirect(returnURL);
    }

    returnURL = client.endSessionUrl({
      post_logout_redirect_uri: returnURL,
      id_token_hint: params.idToken,
    });

    debug('logging out of identity provider, redirecting to %s', returnURL);
    res.redirect(returnURL);
  }
}

export { RequestContext, ResponseContext };
