import { initAuth0, Auth0Server } from '@auth0/nextjs-auth0';

export const pageRouterAuth: Auth0Server = initAuth0({
  auth0Logout: process.env.USE_AUTH0 ? true : false,
  routes: {
    login: '/api/page-router-auth/login',
    callback: '/api/page-router-auth/callback',
    postLogoutRedirect: '/page-router'
  }
});
