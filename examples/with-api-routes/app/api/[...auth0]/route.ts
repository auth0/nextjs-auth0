import { auth0 } from "@/lib/auth0";

// This single file handles all Auth0 routes:
// - /api/auth/login → reconstructed as /auth/login
// - /api/auth/logout → reconstructed as /auth/logout
// - /api/auth/callback → reconstructed as /auth/callback
// - /api/auth/profile → reconstructed as /auth/profile
//
// The catch-all [...auth0] captures the segments after /api/
// e.g., /api/auth/login → params = ["auth", "login"] → "/auth/login"

export const GET = auth0.apiRoute.bind(auth0);
export const POST = auth0.apiRoute.bind(auth0);
