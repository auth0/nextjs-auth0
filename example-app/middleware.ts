import { initAuth0 } from '@auth0/nextjs-auth0/edge';

const auth0 = initAuth0({ routes: { login: '/api/page-router-auth/login' } });

export default auth0.withMiddlewareAuthRequired();

export const config = {
  matcher: ['/page-router/profile-middleware', '/profile-middleware']
};
