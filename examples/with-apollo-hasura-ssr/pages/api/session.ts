import { NextApiRequest, NextApiResponse } from 'next'
import auth0 from '../../lib/auth0'

export default async function session(req: NextApiRequest, res: NextApiResponse) {
  try {
    const s = await auth0.getSession(req)
    res.json(s)
  } catch (error) {
    console.error(error)
    if (res.writable) {
      res.status(error.status || 500).json({
        error: true,
        message: 'Internal server error',
        code: 500,
      })
    }
  }
}