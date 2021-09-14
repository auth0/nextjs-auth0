import nock from 'nock';
import { JSONWebKeySet } from 'jose';
import { ConfigParameters } from '../../src';
import { makeIdToken } from '../auth0-session/fixtures/cert';

export function discovery(params: ConfigParameters, discoveryOptions?: any): nock.Scope {
  const { error, ...metadata } = discoveryOptions || {};

  if (error) {
    return nock(params.issuerBaseURL as string)
      .get('/.well-known/openid-configuration')
      .reply(500, { error })
      .get('/.well-known/oauth-authorization-server')
      .reply(500, { error });
  }

  return nock(params.issuerBaseURL as string)
    .get('/.well-known/openid-configuration')
    .reply(200, () => {
      return {
        issuer: `${params.issuerBaseURL}/`,
        authorization_endpoint: `${params.issuerBaseURL}/authorize`,
        token_endpoint: `${params.issuerBaseURL}/oauth/token`,
        userinfo_endpoint: `${params.issuerBaseURL}/userinfo`,
        jwks_uri: `${params.issuerBaseURL}/.well-known/jwks.json`,
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
        ...metadata
      };
    });
}

export function userInfoWithDelay(params: ConfigParameters, delay: number): nock.Scope {
  return nock(params.issuerBaseURL as string)
    .get('/userinfo')
    .reply((_uri, _requestBody, cb) => {
      setTimeout(() => cb(null, [200, {}]), delay);
    });
}

export function jwksEndpoint(params: ConfigParameters, keyset: JSONWebKeySet): nock.Scope {
  return nock(params.issuerBaseURL as string)
    .get('/.well-known/jwks.json')
    .reply(200, keyset);
}

export function codeExchange(params: ConfigParameters, idToken: string, code = 'code'): nock.Scope {
  return nock(`${params.issuerBaseURL}`)
    .post(
      '/oauth/token',
      `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(
        `${params.baseURL}api/auth/callback`
      )}`
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

export function refreshTokenExchange(
  params: ConfigParameters,
  refreshToken: string,
  payload: Record<string, unknown>,
  newToken?: string
): nock.Scope {
  const idToken = makeIdToken({
    iss: `${params.issuerBaseURL}/`,
    aud: params.clientID,
    ...payload
  });

  return nock(`${params.issuerBaseURL}`)
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
  params: ConfigParameters,
  refreshToken: string,
  payload: Record<string, unknown>,
  newToken?: string,
  newrefreshToken?: string
): nock.Scope {
  const idToken = makeIdToken({
    iss: `${params.issuerBaseURL}/`,
    aud: params.clientID,
    ...payload
  });

  return nock(`${params.issuerBaseURL}`)
    .post('/oauth/token', `grant_type=refresh_token&refresh_token=${refreshToken}`)
    .reply(200, {
      access_token: newToken || 'eyJz93a...k4laUWw',
      refresh_token: newrefreshToken || 'GEbRxBN...edjnXbL',
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: 750,
      scope: 'read:foo write:foo'
    });
}

export function userInfo(params: ConfigParameters, token: string, payload: Record<string, unknown>): nock.Scope {
  return nock(`${params.issuerBaseURL}`, {
    reqheaders: {
      authorization: `Bearer ${token}`
    }
  })
    .get('/userinfo')
    .reply(200, payload);
}
