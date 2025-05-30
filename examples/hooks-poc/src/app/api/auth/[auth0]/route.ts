import { NextRequest, NextResponse } from 'next/server';
import {Auth0Client, LoginOptions, LogoutOptions, TransactionState } from '@auth0/nextjs-auth0/server' // Try dist/edge path

const client = new Auth0Client({
  // Ensure these are set in your .env.local or environment variables
  domain: process.env.AUTH0_ISSUER_BASE_URL!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  secret: process.env.AUTH0_SECRET!,
  appBaseUrl: process.env.AUTH0_BASE_URL!,
  routes: {
    login: '/api/auth/login',
    logout: '/api/auth/logout',
    callback: '/api/auth/callback',
  },
  beforeLogin: async (request: NextRequest, options: LoginOptions): Promise<LoginOptions | NextResponse | void> => {
    console.log('beforeLogin hook triggered.');
    options.returnTo = '/profile-from-hook';
    const url = new URL(request.url!)
    if (url.searchParams.get('blockLogin') === 'true') {
      return NextResponse.redirect(new URL('/login-blocked', request.url));
    }
    return options;
  },
  afterLogout: async (request: NextRequest, response: NextResponse, options: LogoutOptions): Promise<LogoutOptions | NextResponse | void> => {
    console.log('afterLogout hook triggered.');
    const returnToUrl = new URL(options.returnTo || '/', process.env.AUTH0_BASE_URL || 'http://localhost:3000');
    returnToUrl.searchParams.set('logoutHook', 'true');
    options.returnTo = returnToUrl.toString();
    return options; 
  },
  beforeCallback: async (request: NextRequest, state: TransactionState | null): Promise<NextResponse | void> => {
    console.log('beforeCallback hook triggered.');
    if (state) {
      console.log('Transaction state object:', state);
      if (state.state) { 
        console.log('OAuth state parameter value:', state.state);
      }
      if (state.returnTo === '/profile-from-hook') {
        console.log('Special returnTo detected in beforeCallback.');
      }
    }
    const url = new URL(request.url!);
    if (url.searchParams.get('error') === 'access_denied') {
      console.log('Access denied error detected in beforeCallback.');
      return NextResponse.redirect(new URL('/access-denied', request.url));
    }
  },
});

export async function GET(req: NextRequest, { params }: { params: { auth0: string[] } }) {
  return client.handler(req);
}

// If you need POST for backchannel logout (not explicitly requested, but good practice)
// export async function POST(req: NextRequest, { params }: { params: { auth0: string[] } }) {
//   return client.handler(req);
// } 