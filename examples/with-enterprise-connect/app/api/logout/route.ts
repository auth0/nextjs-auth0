import { NextResponse } from "next/server";

export async function GET() {
  // Clear the app session cookie, then delegate to the SDK's /auth/logout route.
  // In EC mode the SDK constructs the correct /oidc/logout URL with federated=true
  // automatically — no manual URL construction needed.
  const res = NextResponse.redirect(
    new URL("/auth/logout?federated=true&returnTo=/login", process.env.APP_BASE_URL)
  );
  res.cookies.set("app_session", "", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0
  });

  return res;
}
