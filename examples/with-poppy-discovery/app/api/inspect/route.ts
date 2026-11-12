import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

// Runs one SDK method on the server and returns what it says about this
// browser. Used by the buttons on the home page.
export async function GET(request: Request) {
  const call = new URL(request.url).searchParams.get("call");

  switch (call) {
    case "poppy.getContext":
      return json(await auth0.poppy.getContext());

    case "getSession": {
      const session = await auth0.getSession();
      // Leave the tokens out: this is a demo, and a browser doesn't need them.
      return json(
        session && {
          user: session.user,
          scope: session.tokenSet.scope,
          expiresAt: session.tokenSet.expiresAt,
          internal: session.internal
        }
      );
    }

    case "getAnonymousSession": {
      const guest = await auth0.getAnonymousSession();
      return json(guest && { id: guest.id, expiresAt: guest.expiresAt });
    }

    default:
      return json({ error: `Unknown call: ${call}` }, 400);
  }
}

function json(body: unknown, status = 200) {
  return NextResponse.json(body, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}
