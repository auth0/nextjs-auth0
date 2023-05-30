import { NextApiRequest, NextApiResponse } from 'next';
import { Session, LoginOptions } from '@auth0/nextjs-auth0';
import { pageRouterAuth } from '../../../lib/auth0';

export default pageRouterAuth.handleAuth({
  login: pageRouterAuth.handleLogin({
    authorizationParams: { redirect_uri: `${process.env.AUTH0_BASE_URL}/api/page-router-auth/callback` },
    getLoginState(req: NextApiRequest, options: LoginOptions) {
      return {
        returnTo: options.returnTo,
        foo: 'bar'
      };
    }
  }),
  callback: pageRouterAuth.handleCallback({
    redirectUri: `${process.env.AUTH0_BASE_URL}/api/page-router-auth/callback`,
    afterCallback(_req: NextApiRequest, _res: NextApiResponse, session: Session) {
      return { ...session, foo: 'bar' };
    }
  }),
  me: pageRouterAuth.handleProfile({
    refetch: true,
    afterRefetch(req: NextApiRequest, res: NextApiResponse, session: Session) {
      return { ...session, foo: 'bar' };
    }
  }),
  logout: pageRouterAuth.handleLogout({ returnTo: `${process.env.AUTH0_BASE_URL}/page-router` })
});
