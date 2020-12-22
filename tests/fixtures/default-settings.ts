import { ConfigParameters } from '../../src';

export const withoutApi: ConfigParameters = {
  issuerBaseURL: 'https://acme.auth0.local',
  clientID: '__test_client_id__',
  clientSecret: 'client_secret',
  baseURL: 'http://www.acme.com/',
  secret: '__test_session_secret__'
};

/**
 * Default settings which include an audience.
 */
export const withApi: ConfigParameters = {
  issuerBaseURL: 'https://acme.auth0.local',
  clientID: '__test_client_id__',
  clientSecret: 'client_secret',
  baseURL: 'http://www.acme.com/',
  secret: '__test_session_secret__',
  authorizationParams: {
    scope: 'openid profile read:customer',
    audience: 'https://api.acme.com'
  }
};
