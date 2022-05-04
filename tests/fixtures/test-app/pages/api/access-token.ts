import { NextApiRequest, NextApiResponse } from 'next';

export default async function accessTokenHandler(req: NextApiRequest, res: NextApiResponse): Promise<void> {
  try {
    const json = await (global as any).getAccessToken(req, res);
    res.status(200).json(json);
  } catch (error) {
    res.statusMessage = error.message;
    res.status(error.status || 500).end(error.message);
  }
}
