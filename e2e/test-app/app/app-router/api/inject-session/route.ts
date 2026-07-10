import { NextRequest, NextResponse } from "next/server";
import { generateSessionCookie } from "@auth0/nextjs-auth0/testing";

// TEST-ONLY: sets a pre-built session cookie so specs can skip the Auth0 login UI.
export async function POST(req: NextRequest) {
  const body = await req.json();
  const secret = process.env.AUTH0_SECRET!;

  const cookie = await generateSessionCookie(
    {
      user: body.user ?? { sub: "test|user123", email: "testuser@example.com", name: "Test User" },
      tokenSet: body.tokenSet ?? {
        accessToken: "test-access-token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      },
      ...(body.internal && { internal: body.internal }),
    },
    { secret }
  );

  const res = NextResponse.json({ ok: true });
  res.cookies.set("__session", cookie, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 3600,
  });
  return res;
}
