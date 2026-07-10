import type { NextApiRequest, NextApiResponse } from "next";
import { auth0 } from "@/lib/auth0";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await auth0.getSession(req);
  if (!session) return res.status(401).json({ error: "Unauthorized" });
  await auth0.updateSession(req, res, {
    ...session,
    user: { ...session.user, updatedAt: Date.now() },
  });
  res.status(200).json({ ok: true });
}
