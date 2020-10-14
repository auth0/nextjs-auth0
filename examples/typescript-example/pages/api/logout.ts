import { NextApiRequest, NextApiResponse } from 'next';

import auth0 from '../../lib/auth0';

export default async function logout(req: NextApiRequest, res: NextApiResponse): Promise<void> {
  try {
    await auth0.handleLogout(req, res);
  } catch (error) {
    console.error(error);
    res.status(error.status || 500).end(error.message);
  }
}
