import { NextRequest, NextResponse } from "next/server";
import {
  AnonymousSessionError,
  getStatusForAnonymousError
} from "@auth0/nextjs-auth0/errors";

import { auth0 } from "@/lib/auth0";

export async function POST(req: NextRequest) {
  try {
    // Read the request body from a CLONE. Under the Next.js 16 proxy runtime the
    // handler receives a plain `Request` (not a `NextRequest`), and the SDK
    // internally rebuilds a `NextRequest` from it, reusing the original body
    // stream. If we consume `req.body` here via `req.json()`, that rebuild fails
    // with "Response body object should not be disturbed or locked". Cloning
    // leaves `req`'s stream intact for the SDK.
    const body = await req.clone().json();
    const metadata = body.metadata || undefined;

    // The SDK writes the encrypted `auth0_anon` cookie onto `res.cookies`. We
    // must return that SAME response so the Set-Cookie header reaches the
    // client. Passing `res` as the second arg to NextResponse.json() copies its
    // headers (incl. Set-Cookie) and status onto the JSON response.
    const res = NextResponse.json(null, { status: 201 });
    const session = await auth0.createAnonymousSession(req, res, { metadata });

    return NextResponse.json(session, res);
  } catch (err: any) {
    console.error("[POST /api/anon/create] Error:", err);
    if (err instanceof AnonymousSessionError) {
      return NextResponse.json(
        {
          code: err.code,
          message: err.message
        },
        { status: getStatusForAnonymousError(err.code) }
      );
    }
    return NextResponse.json(
      {
        code: "internal_error",
        message: err.message || "Failed to create anonymous session"
      },
      { status: 500 }
    );
  }
}
