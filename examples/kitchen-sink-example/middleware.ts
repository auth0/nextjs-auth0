import { withMiddlewareAuthRequired } from '@auth0/nextjs-auth0/middleware';

export default withMiddlewareAuthRequired();

export const config = {
  matcher: '/profile-mw'
};
