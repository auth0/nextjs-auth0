import { NextRequest, NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

export async function GET(req: NextRequest) {
  try {
    const anonymousSession = await auth0.getAnonymousSession(req);

    if (!anonymousSession) {
      return NextResponse.json(
        { error: "No anonymous session found" },
        { status: 401 }
      );
    }

    // Use access token to call protected API (stub/echo since api.customers may not have real endpoints)
    // In production, this would be: fetch(`${process.env.AUTH0_AUDIENCE}/products`, { headers: { Authorization: `Bearer ${anonymousSession.accessToken}` } })

    // For demo: echo token info and simulate success
    const response = {
      message:
        "Successfully fetched products using anonymous session access token",
      audience: process.env.AUTH0_AUDIENCE,
      scope: "read:customers",
      tokenPreview: anonymousSession.accessToken.substring(0, 30) + "...",
      expiresAt: new Date(anonymousSession.expiresAt * 1000).toISOString(),
      // Stub product data
      products: [
        { id: 1, name: "Product A", price: 29.99 },
        { id: 2, name: "Product B", price: 49.99 }
      ]
    };

    return NextResponse.json(response, { status: 200 });
  } catch (err: any) {
    console.error("[GET /api/products] Error:", err);
    return NextResponse.json(
      { error: err.message || "Failed to fetch products" },
      { status: 500 }
    );
  }
}
