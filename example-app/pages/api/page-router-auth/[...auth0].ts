import { pageRouterAuth } from '@/lib/auth0';

const redirectUri = `${process.env.AUTH0_BASE_URL}/api/page-router-auth/callback`;

export default pageRouterAuth.handleAuth({
  login: pageRouterAuth.handleLogin({
    authorizationParams: { redirect_uri: redirectUri }
  }),
  callback: pageRouterAuth.handleCallback({ redirectUri }),
  logout: pageRouterAuth.handleLogout({ returnTo: `${process.env.AUTH0_BASE_URL}/page-router` })
});
