import { initAuth0 } from '@auth0/nextjs-auth0';

function getServerSetting(environmentVariable: string, defaultValue?: string) {
  if (typeof window === 'undefined') {
    return process.env[environmentVariable];
  }

  return defaultValue || null;
}

export default initAuth0({
  clientId: getServerSetting('AUTH0_CLIENT_ID'),
  clientSecret: getServerSetting('AUTH0_CLIENT_SECRET'),
  scope: 'openid profile email',
  domain: getServerSetting('AUTH0_DOMAIN'),
  redirectUri: getServerSetting('REDIRECT_URI', 'http://localhost:3000/api/callback'),
  postLogoutRedirectUri: getServerSetting('POST_LOGOUT_REDIRECT_URI', 'http://localhost:3000/'),
  session: {
    cookieSecret: getServerSetting('SESSION_COOKIE_SECRET'),
    cookieLifetime: 7200,
    storeIdToken: false,
    storeRefreshToken: false,
    storeAccessToken: false
  }
});
