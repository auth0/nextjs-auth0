import { initAuth0 } from '@auth0/nextjs-auth0';

function getServerSetting(environmentVariable: string, defaultValue?: string): string | null {
  if (typeof window === 'undefined') {
    return process.env[environmentVariable];
  }

  return defaultValue || null;
}

const baseURL = 'http://localhost:3000'
const callback = '/api/callback'; // @TODO

export default initAuth0({
  baseURL,
  clientID: getServerSetting('AUTH0_CLIENT_ID'),
  clientSecret: getServerSetting('AUTH0_CLIENT_SECRET'),
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
  auth0Logout: true,
  session: {
    cookie: {
      path: '/'
    },
  },
  authorizationParams: {
    response_type: 'code',
    audience: getServerSetting('API_AUDIENCE'),
    scope: getServerSetting('AUTH0_SCOPE'),
  },
  routes: {
    callback,
    postLogoutRedirect: getServerSetting('POST_LOGOUT_REDIRECT_URI')
  },
  secret: getServerSetting('SESSION_COOKIE_SECRET'),
});
