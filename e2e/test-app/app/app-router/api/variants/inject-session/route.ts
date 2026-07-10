import { NextRequest, NextResponse } from "next/server";
import { generateSessionCookie } from "@auth0/nextjs-auth0/testing";

// Injects a session using a custom cookie name — used by custom-cookie-name variant tests.
export async function POST(req: NextRequest) {
  const body = await req.json();
  const secret = process.env.AUTH0_SECRET!;
  const cookieName: string = body.cookieName ?? "__session";

  const cookie = await generateSessionCookie(
    {
      user: body.user ?? { sub: "test|variant", email: "variant@example.com" },
      tokenSet: body.tokenSet ?? {
        accessToken: "test-access-token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      },
    },
    { secret }
  );

  const res = NextResponse.json({ ok: true });
  res.cookies.set(cookieName, cookie, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 3600,
  });
  return res;
}
