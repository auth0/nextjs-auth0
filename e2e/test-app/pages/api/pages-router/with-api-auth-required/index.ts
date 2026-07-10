import type { NextApiRequest, NextApiResponse } from "next";
import { auth0 } from "@/lib/auth0";

export default auth0.withApiAuthRequired(async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  const session = await auth0.getSession(req);
  res.status(200).json({ sub: session!.user.sub, email: session!.user.email });
});
