import { NextApiRequest, NextApiResponse } from 'next';
import { pageRouterAuth } from '../../lib/auth0';

export default pageRouterAuth.withApiAuthRequired(async function profile(req: NextApiRequest, res: NextApiResponse) {
  const session = await pageRouterAuth.getSession(req, res);

  res.status(200).json(session?.user);
});
