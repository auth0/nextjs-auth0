import { NextApiRequest, NextApiResponse } from 'next';

export default function shows(req: NextApiRequest, res: NextApiResponse): void {
  res.status(200).json({ vercel_url: process.env.VERCEL_URL });
}
