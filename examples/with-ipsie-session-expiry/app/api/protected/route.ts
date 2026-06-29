import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

const handler = auth0.withApiAuthRequired(async () => {
  return NextResponse.json({ protected: true, message: "You have an active session." });
});

// withApiAuthRequired returns AppRouteHandlerFn whose declared return is
// Promise<Response> | Response, but the inferred type comes through as
// unknown due to the SDK's overloaded signature. The cast is safe — the
// runtime always returns a Response.
export async function GET(req: NextRequest): Promise<Response> {
  return handler(req, {}) as Promise<Response>;
}
