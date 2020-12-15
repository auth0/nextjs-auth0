/**
 * Default settings which don't include authorization.
 */
import { ConfigParameters } from '../../src/auth0-session';

export const withoutApi: ConfigParameters = {
  issuerBaseURL: 'https://acme.auth0.local',
  clientID: 'client_id',
  clientSecret: 'client_secret',
  baseURL: 'https://www.acme.com/',
  secret: 'keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat'
};

/**
 * Default settings which include an audience.
 */
export const withApi: ConfigParameters = {
  issuerBaseURL: 'https://acme.auth0.local',
  clientID: 'client_id',
  clientSecret: 'client_secret',
  baseURL: 'https://www.acme.com/',
  secret: 'keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat',
  authorizationParams: {
    scope: 'openid profile read:customer',
    audience: 'https://api.acme.com'
  }
};
