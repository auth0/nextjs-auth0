import { pageRouterAuth } from '@/lib/auth0';
import { NextApiRequest, NextApiResponse } from 'next';

const redirectUri = `${process.env.AUTH0_BASE_URL}/api/page-router-auth/callback`;

export default pageRouterAuth.handleAuth({
  async login(req: NextApiRequest, res: NextApiResponse) {
    await pageRouterAuth.handleLogin(req, res, {
      authorizationParams: {
        custom_param: 'custom'
      },
      returnTo: '/custom-page'
    });
  },
  callback: pageRouterAuth.handleCallback({ redirectUri }),
  logout: pageRouterAuth.handleLogout({ returnTo: `${process.env.AUTH0_BASE_URL}/page-router` })
});
