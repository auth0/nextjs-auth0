import type { NextApiRequest, NextApiResponse } from "next"
import { SessionData } from "@auth0/nextjs-auth0/types"

import { auth0 } from "@/lib/auth0"

type ResponseData = SessionData | { error: string }

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<ResponseData>
) {
  const session = await auth0.getSession(req)

  if (!session) {
    return res.status(401).json({ error: "Unauthorized" })
  }

  res.status(200).json(session)
}
