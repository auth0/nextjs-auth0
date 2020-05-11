import nock from 'nock';
import { JSONWebKeySet, JWK } from '@panva/jose';

import createToken from './tokens';
import IAuth0Settings from '../../src/settings';

export function discovery(settings: IAuth0Settings, discoveryOptions?: any): nock.Scope {
  return nock(`https://${settings.domain}`)
    .get('/.well-known/openid-configuration')
    .reply(200, {
      issuer: `https://${settings.domain}/`,
      authorization_endpoint: `https://${settings.domain}/authorize`,
      token_endpoint: `https://${settings.domain}/oauth/token`,
      userinfo_endpoint: `https://${settings.domain}/userinfo`,
      jwks_uri: `https://${settings.domain}/.well-known/jwks.json`,
      scopes_supported: [
        'openid',
        'profile',
        'offline_access',
        'name',
        'given_name',
        'family_name',
        'nickname',
        'email',
        'email_verified',
        'picture',
        'created_at',
        'identities',
        'phone',
        'address'
      ],
      response_types_supported: ['code'],
      id_token_signing_alg_values_supported: ['RS256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      claims_supported: [
        'aud',
        'auth_time',
        'created_at',
        'email',
        'email_verified',
        'exp',
        'family_name',
        'given_name',
        'iat',
        'identities',
        'iss',
        'name',
        'nickname',
        'phone_number',
        'picture',
        'sub'
      ],
      ...(discoveryOptions || {})
    });
}

export function userInfoWithDelay(settings: IAuth0Settings, delay: number): nock.Scope {
  return nock(`https://${settings.domain}`)
    .get('/userinfo')
    .reply((_uri, _requestBody, cb) => {
      setTimeout(() => cb(null, [200, {}]), delay);
    });
}

export function jwksEndpoint(settings: IAuth0Settings, keyset: JSONWebKeySet): nock.Scope {
  return nock(`https://${settings.domain}`).get('/.well-known/jwks.json').reply(200, keyset);
}

export function codeExchange(
  settings: IAuth0Settings,
  code: string,
  key: JWK.Key,
  payload: object,
  overrides?: object
): nock.Scope {
  const idToken = createToken(key, {
    iss: `https://${settings.domain}/`,
    aud: settings.clientId,
    ...payload,
    ...(overrides || {})
  });

  return nock(`https://${settings.domain}`)
    .post(
      '/oauth/token',
      `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(settings.redirectUri)}`
    )
    .reply(200, {
      access_token: 'eyJz93a...k4laUWw',
      expires_in: 750,
      scope: 'read:foo delete:foo',
      refresh_token: 'GEbRxBN...edjnXbL',
      id_token: idToken,
      token_type: 'Bearer'
    });
}

export function codeExchangeWithTimeout(
  settings: IAuth0Settings,
  code: string,
  key: JWK.Key,
  payload: object,
  overrides?: object
): nock.Scope {
  const idToken = createToken(key, {
    iss: `https://${settings.domain}/`,
    aud: settings.clientId,
    ...payload,
    ...(overrides || {})
  });

  return nock(`https://${settings.domain}`)
    .post(
      '/oauth/token',
      `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(settings.redirectUri)}`
    )
    .reply((_uri, _requestBody, cb) => {
      setTimeout(
        () =>
          cb(null, [
            200,
            {
              access_token: 'eyJz93a...k4laUWw',
              expires_in: 750,
              scope: 'read:foo delete:foo',
              refresh_token: 'GEbRxBN...edjnXbL',
              id_token: idToken,
              token_type: 'Bearer'
            }
          ]),
        500
      );
    });
}

export function codeExchangeWithAccessToken(
  settings: IAuth0Settings,
  code: string,
  key: JWK.Key,
  payload: object,
  overrides?: object
): nock.Scope {
  const idToken = createToken(key, {
    iss: `https://${settings.domain}/`,
    aud: settings.clientId,
    ...payload,
    ...(overrides || {})
  });

  return nock(`https://${settings.domain}`)
    .post(
      '/oauth/token',
      `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(settings.redirectUri)}`
    )
    .reply(200, {
      access_token: 'an_access_token',
      expires_in: 750,
      scope: 'read:foo delete:foo',
      id_token: idToken,
      token_type: 'Bearer'
    });
}

export function refreshTokenExchange(
  settings: IAuth0Settings,
  refreshToken: string,
  key: JWK.Key,
  payload: object,
  newToken?: string
): nock.Scope {
  const idToken = createToken(key, {
    iss: `https://${settings.domain}/`,
    aud: settings.clientId,
    ...payload
  });

  return nock(`https://${settings.domain}`)
    .post('/oauth/token', `grant_type=refresh_token&refresh_token=${refreshToken}`)
    .reply(200, {
      access_token: newToken || 'eyJz93a...k4laUWw',
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: 750,
      scope: 'read:foo write:foo'
    });
}

export function refreshTokenRotationExchange(
  settings: IAuth0Settings,
  refreshToken: string,
  key: JWK.Key,
  payload: object,
  newToken?: string
): nock.Scope {
  const idToken = createToken(key, {
    iss: `https://${settings.domain}/`,
    aud: settings.clientId,
    ...payload
  });

  return nock(`https://${settings.domain}`)
    .post('/oauth/token', `grant_type=refresh_token&refresh_token=${refreshToken}`)
    .reply(200, {
      access_token: newToken || 'eyJz93a...k4laUWw',
      refresh_token: 'GEbRxBN...edjnXbL',
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: 750,
      scope: 'read:foo write:foo'
    });
}

export function userInfo(settings: IAuth0Settings, token: string, payload: object): nock.Scope {
  return nock(`https://${settings.domain}`, {
    reqheaders: {
      authorization: `Bearer ${token}`
    }
  })
    .get('/userinfo')
    .reply(200, payload);
}
