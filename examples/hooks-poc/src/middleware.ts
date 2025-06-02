import { NextRequest } from 'next/server';
import { client } from '@/lib/auth0';

export async function middleware(request: NextRequest) {
  // Pass the request to the Auth0 client's middleware handler.
  // This will automatically handle login, logout, callback, etc.
  return client.middleware(request);
}

export const config = {
  // Matcher specifies the routes on which this middleware should run.
  // This pattern covers all routes under /api/auth/
  matcher: '/api/auth/:path*',
}; 