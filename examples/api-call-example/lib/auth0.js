import { initAuth0 } from '@auth0/nextjs-auth0';

const baseURL = 'http://localhost:3000'
const callback = '/api/callback'; // @TODO

export default initAuth0({
  baseURL,
  clientID: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
  auth0Logout: true,
  session: {
    cookie: {
      path: '/'
    },
  },
  authorizationParams: {
    response_type: 'code',
    audience: process.env.API_AUDIENCE,
    scope: process.env.AUTH0_SCOPE,
  },
  routes: {
    callback,
    postLogoutRedirect: process.env.POST_LOGOUT_REDIRECT_URI
  },
  secret: process.env.SESSION_COOKIE_SECRET,
});
