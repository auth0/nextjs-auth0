import { NextApiRequest, NextApiResponse } from 'next';

export default (global as any).withApiAuthRequired(function protectedApiRoute(
  _req: NextApiRequest,
  res: NextApiResponse
) {
  res.status(200).json({ foo: 'bar' });
});
