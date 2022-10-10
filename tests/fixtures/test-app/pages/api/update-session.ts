import { NextApiRequest, NextApiResponse } from 'next';

export default async function sessionHandler(req: NextApiRequest, res: NextApiResponse): Promise<void> {
  const session = await global.getSession?.(req, res);
  const updated = { ...session, ...req.body?.session };
  await global.updateSession?.(req, res, updated);
  res.status(200).json(updated);
}
