/**
 * Default settings which don't include authorization.
 */
export const withoutApi = {
  domain: 'acme.auth0.local',
  clientId: 'client_id',
  clientSecret: 'client_secret',
  redirectUri: 'https://www.acme.com/callback',
  postLogoutRedirectUri: 'https://www.acme.com',
  scope: 'openid profile',
  session: {
    cookieSecret: 'keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat'
  }
};

/**
 * Default settings which include an audience.
 */
export const withApi = {
  domain: 'acme.auth0.local',
  clientId: 'client_id',
  clientSecret: 'client_secret',
  redirectUri: 'https://www.acme.com/callback',
  postLogoutRedirectUri: 'https://www.acme.com',
  scope: 'openid profile read:customer',
  audience: 'https://api.acme.com',
  session: {
    cookieSecret: 'keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat.keyboardcat'
  }
};
