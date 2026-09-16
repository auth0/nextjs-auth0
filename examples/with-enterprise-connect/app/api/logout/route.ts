import { NextRequest, NextResponse } from "next/server";

// Logout is a state-changing action, so it must not be reachable via a
// cross-site top-level GET (which would let a malicious page log the user out).
// Require POST and verify the request originates from this app before clearing
// the session. The dashboard submits this via a form button, not a link.
export async function POST(req: NextRequest) {
  const appBaseUrl = process.env.APP_BASE_URL!;
  const appOrigin = new URL(appBaseUrl).origin;

  // Same-origin check: the Origin header is set by the browser on form POSTs and
  // cannot be forged by cross-site script. Reject anything that is not this app.
  const origin = req.headers.get("origin");
  if (origin !== appOrigin) {
    return new NextResponse("Invalid origin", { status: 403 });
  }

  // Clear the app session cookie, then delegate to the SDK's /auth/logout route.
  // returnTo becomes the OIDC post_logout_redirect_uri, which Auth0 requires to be
  // an absolute URL matching an Allowed Logout URL, so pass the full origin here.
  const logoutUrl = new URL("/auth/logout", appBaseUrl);
  logoutUrl.searchParams.set("federated", "true");
  logoutUrl.searchParams.set(
    "returnTo",
    new URL("/login", appBaseUrl).toString()
  );
  // 303 See Other: the browser follows this POST redirect with a GET, which the
  // SDK's /auth/logout route expects. A default 307 would re-POST and fail.
  const res = NextResponse.redirect(logoutUrl, 303);
  res.cookies.set("app_session", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 0
  });

  return res;
}
