import { initAuth0, Auth0Server } from '@auth0/nextjs-auth0';

export const pageRouterAuth: Auth0Server = initAuth0({
  auth0Logout: !(process.env.AUTH0_ISSUER_BASE_URL as string).startsWith('http://localhost'),
  routes: {
    login: '/api/page-router-auth/login',
    callback: '/api/page-router-auth/callback',
    postLogoutRedirect: '/page-router'
  }
});
