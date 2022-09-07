import { NextApiRequest, NextApiResponse } from 'next';

export default async function sessionHandler(req: NextApiRequest, res: NextApiResponse) {
  const session = await (global as any).getSession(req, res);
  const updated = { ...session?.user, ...req.body?.user };
  await (global as any).updateUser(req, res, updated);
  res.status(200).json(updated);
}
