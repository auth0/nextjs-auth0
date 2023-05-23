import { pageRouterAuth } from '../../../lib/auth0';

export default pageRouterAuth.handleAuth({
  login: pageRouterAuth.handleLogin({
    authorizationParams: { redirect_uri: `${process.env.AUTH0_BASE_URL}/api/page-router-auth/callback` }
  }),
  callback: pageRouterAuth.handleCallback({
    redirectUri: `${process.env.AUTH0_BASE_URL}/api/page-router-auth/callback`
  })
});
