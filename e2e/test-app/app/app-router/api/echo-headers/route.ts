import { NextRequest, NextResponse } from "next/server";

// Returns the request headers as JSON — used by auth-fetcher tests to verify
// that fetchWithAuth() sends the correct Authorization: Bearer header.
export async function GET(req: NextRequest) {
  const headers: Record<string, string> = {};
  req.headers.forEach((value, key) => {
    headers[key] = value;
  });
  return NextResponse.json({ headers });
}
