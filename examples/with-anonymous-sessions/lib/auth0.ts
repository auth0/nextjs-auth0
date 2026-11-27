import { NextResponse } from "next/server";
import { Auth0Client } from "@auth0/nextjs-auth0/server";

import { mockAnonFetch } from "./mock/anon-mock-fetch";

export const auth0 = new Auth0Client({
  // TEST-ONLY: offline e2e mock (E2E_ANON_MOCK=1). Never set this env var in production. See lib/mock/.
  ...(process.env.E2E_ANON_MOCK === "1" && { customFetch: mockAnonFetch }),
  anonymousSession: {
    enabled: true,
    audience: process.env.AUTH0_AUDIENCE,
    scope: "read:customers",
    cookie: {
      name: "auth0_anon",
      sameSite: "lax",
      // Cookies are Secure everywhere except plain-http local development.
      secure: process.env.NODE_ENV === "production",
      maxAge: 2592000 // 30 days
    }
  },
  onCallback: async (error, ctx, session) => {
    if (error) {
      return NextResponse.redirect(
        new URL(
          "/?error=callback_failed",
          ctx.appBaseUrl || "http://localhost:3000"
        )
      );
    }
    const appBaseUrl = ctx.appBaseUrl || "http://localhost:3000";
    const destination = new URL(ctx.returnTo || "/", appBaseUrl);

    // When the anonymous session was successfully linked to the now-authenticated
    // user, surface it to the client so the demo can render the "linked" banner.
    // ctx.anonymousSessionLinked is true when the anon cookie present at login still
    // matches the digest the SDK bound to the login transaction. We only add a UI hint; no
    // session_token or other reserved data is ever placed in the URL.
    if (ctx.anonymousSessionLinked && session) {
      destination.searchParams.set("linked", "true");
    }

    return NextResponse.redirect(destination);
  }
});
