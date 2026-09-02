import { auth0 } from "@/lib/auth0";
import { NextRequest, NextResponse } from "next/server";

/**
 * POST /api/login
 *
 * Route handler entry point for Enterprise Connect login. This is the correct
 * context for auth0.startEnterpriseLogin() because route handlers return the
 * NextResponse directly to the browser — the transaction cookie set by
 * startInteractiveLogin rides on that response and survives to /auth/callback.
 *
 * Server actions cannot be used here: they cannot propagate the transaction
 * cookie because they do not return the NextResponse to the browser.
 */
export async function POST(req: NextRequest) {
  const formData = await req.formData();
  const email = String(formData.get("email") ?? "");

  if (!email || !email.includes("@")) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  const res = await auth0.startEnterpriseLogin({
    email,
    returnTo: "/dashboard"
  });

  if (res) {
    // startEnterpriseLogin returns a 307 redirect. A 307 PRESERVES the request
    // method, so the browser would try to POST to Auth0's /authorize endpoint
    // (which only accepts GET) and login would fail. Re-emit as 303 See Other
    // to force the browser to switch to GET, and carry over the transaction
    // (__txn_*) cookie that startEnterpriseLogin attached to the original
    // response so it survives to /auth/callback.
    const location = res.headers.get("location");
    if (!location) return res;

    const redirect = NextResponse.redirect(location, 303);
    for (const cookie of res.cookies.getAll()) {
      redirect.cookies.set(cookie);
    }
    return redirect;
  }

  // Not federated — redirect back to login with a query param for the error
  const loginUrl = new URL("/login", req.url);
  loginUrl.searchParams.set("error", "not-federated");
  return NextResponse.redirect(loginUrl);
}
