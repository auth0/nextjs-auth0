import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

const protectedHandler = auth0.withApiAuthRequired(async (_req: Request | NextRequest) => {
  return NextResponse.json({ protected: true, message: "You have an active session." });
});

export async function GET(req: NextRequest): Promise<NextResponse> {
  return protectedHandler(req, {}) as Promise<NextResponse>;
}
