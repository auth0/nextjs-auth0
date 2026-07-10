import type { NextApiRequest, NextApiResponse } from "next";
import { generateSessionCookie } from "@auth0/nextjs-auth0/testing";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const secret = process.env.AUTH0_SECRET!;
  const body = req.body;

  const cookie = await generateSessionCookie(
    {
      user: body.user ?? { sub: "test|user123", email: "testuser@example.com", name: "Test User" },
      tokenSet: body.tokenSet ?? {
        accessToken: "test-access-token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      },
    },
    { secret }
  );

  res.setHeader("Set-Cookie", `__session=${cookie}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`);
  res.status(200).json({ ok: true });
}
