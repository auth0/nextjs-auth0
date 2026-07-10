import { NextRequest, NextResponse } from "next/server";
import { auth0ShortAbsoluteDuration } from "@/lib/auth0-config-variants";

// Returns a session injected via the short-lived Auth0Client (absoluteDuration=1s).
// GET — read session (401 if expired / absent)
// POST — inject a session with a backdated createdAt so absoluteDuration is already expired
export async function GET() {
  const session = await auth0ShortAbsoluteDuration.getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  return NextResponse.json({ user: session.user, internal: session.internal });
}

// Injects a session whose internal.createdAt is in the past so absoluteDuration
// has already been exceeded. The client then sees it as expired.
export async function POST(req: NextRequest) {
  const { generateSessionCookie } = await import("@auth0/nextjs-auth0/testing");
  const body = await req.json().catch(() => ({}));
  const secret = process.env.AUTH0_SECRET!;

  const createdAt = body.createdAt ?? Math.floor(Date.now() / 1000) - 10;

  const cookie = await generateSessionCookie(
    {
      user: body.user ?? { sub: "test|short001", email: "short@example.com" },
      tokenSet: body.tokenSet ?? {
        accessToken: "short-session-token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      },
      internal: { sid: "test-sid", createdAt },
    },
    { secret }
  );

  // absoluteDuration = 1 second. maxAge = createdAt + 1 - now.
  // For backdated createdAt, this is negative → cookie is immediately expired.
  const absoluteDuration = 1;
  const maxAge = Math.max(0, createdAt + absoluteDuration - Math.floor(Date.now() / 1000));

  const res = NextResponse.json({ ok: true });
  res.cookies.set("__session", cookie, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge,
  });
  return res;
}
