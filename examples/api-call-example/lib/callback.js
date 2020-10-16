import createError from 'http-errors';
import { decodeState } from 'express-openid-connect/lib/hooks/getLoginState';
import { get as getClient } from 'express-openid-connect/lib/client';

module.exports = async (req, res, config, transient, resOidc) => {
  const client = await getClient(config);
  if (!client) {
    return;
  }

  const redirectUri = resOidc.getRedirectUri();

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

  const { returnTo } = decodeState(expectedState);

  // intentional clone of the properties on tokenSet
  Object.assign(req[config.session.name], {
    id_token: tokenSet.id_token,
    access_token: tokenSet.access_token,
    refresh_token: tokenSet.refresh_token,
    token_type: tokenSet.token_type,
    expires_at: tokenSet.expires_at,
  });

  // attemptSilentLogin.resumeSilentLogin(req, res);

  res.redirect(returnTo || config.baseURL)
};
