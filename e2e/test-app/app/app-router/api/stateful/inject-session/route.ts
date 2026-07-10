import { NextRequest, NextResponse } from "next/server";
import { generateSessionCookie } from "@auth0/nextjs-auth0/testing";

// Injects a stateful session: writes the session cookie that the stateful client reads.
// The stateful client stores data in SQLite; the cookie only carries an opaque session ID.
// To make the cookie valid for the stateful client we use the same secret.
export async function POST(req: NextRequest) {
  const body = await req.json();
  const secret = process.env.AUTH0_SECRET!;

  const cookie = await generateSessionCookie(
    {
      user: body.user ?? { sub: "stateful|001", email: "stateful@example.com" },
      tokenSet: body.tokenSet ?? {
        accessToken: "stateful-access-token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      },
      ...(body.internal && { internal: body.internal }),
    },
    { secret }
  );

  const res = NextResponse.json({ ok: true });
  res.cookies.set("__session_stateful", cookie, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 3600,
  });
  return res;
}
