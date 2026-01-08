import { auth0 } from "@/lib/auth0";
import { NextRequest } from "next/server";

// This single file handles all Auth0 routes:
// - GET /api/auth/login
// - GET /api/auth/logout
// - GET /api/auth/callback
// - POST /api/auth/backchannel-logout
// - GET /api/auth/profile
// - GET /api/auth/access-token
//
// The catch-all [...auth0] captures the segments after /api/
// e.g., /api/auth/login → params = ["auth", "login"] → "/auth/login"

export const GET = (request: NextRequest) => auth0.handleAuth(request);
export const POST = (request: NextRequest) => auth0.handleAuth(request);