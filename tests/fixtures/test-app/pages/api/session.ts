import { NextApiRequest, NextApiResponse } from 'next';

export default async function sessionHandler(req: NextApiRequest, res: NextApiResponse) {
  const json = await global.getSession?.(req, res);
  res.status(200).json(json);
}
