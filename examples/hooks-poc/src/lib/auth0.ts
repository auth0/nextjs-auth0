import { NextRequest, NextResponse } from 'next/server';
import { Auth0Client, LoginOptions, LogoutOptions, TransactionState } from '@auth0/nextjs-auth0/server';

export const client = new Auth0Client({
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
  afterLogout: async (request: NextRequest, response: NextResponse, options: LogoutOptions): Promise<NextResponse | void> => {
    console.log('afterLogout hook triggered.');
    const baseReturnTo = options.returnTo || '/';
    const appBaseUrl = process.env.AUTH0_BASE_URL || 'http://localhost:3000';

    const finalRedirectUrl = new URL(baseReturnTo, appBaseUrl);
    finalRedirectUrl.searchParams.set('logoutHook', 'true');

    // Return a new NextResponse that redirects to the modified URL
    return NextResponse.redirect(finalRedirectUrl.toString());
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
    const url = new URL(request.url);
    if (url.searchParams.get('error') === 'access_denied') {
      console.log('Access denied error detected in beforeCallback.');
      return NextResponse.redirect(new URL('/access-denied', request.url));
    }
  },
}); 