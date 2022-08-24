import { NextApiRequest, NextApiResponse } from 'next';

export default function sessionHandler(req: NextApiRequest, res: NextApiResponse): void {
  const session = (global as any).getSession(req, res);
  const updated = { ...session?.user, ...req.body?.user };
  (global as any).updateUser(req, res, updated);
  res.status(200).json(updated);
}
