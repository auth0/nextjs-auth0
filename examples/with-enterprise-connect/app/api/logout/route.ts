import { NextResponse } from "next/server";

export async function GET() {
  // Clear the app session cookie, then delegate to the SDK's /auth/logout route.
  // returnTo becomes the OIDC post_logout_redirect_uri, which Auth0 requires to be
  // an absolute URL matching an Allowed Logout URL, so pass the full origin here.
  const logoutUrl = new URL("/auth/logout", process.env.APP_BASE_URL);
  logoutUrl.searchParams.set("federated", "true");
  logoutUrl.searchParams.set(
    "returnTo",
    new URL("/login", process.env.APP_BASE_URL).toString()
  );
  const res = NextResponse.redirect(logoutUrl);
  res.cookies.set("app_session", "", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0
  });

  return res;
}
