import { NextRequest, NextResponse } from 'next/server';
import { auth0 } from '../../../../lib/auth0';

export const GET = async (req: NextRequest) => {
  try {
    const session = await auth0.getSession();
    if (!session) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    // The request has path /my-org/identity-providers, we need to proxy it to Auth0's API
    // Build the actual Auth0 endpoint based on the issuer
    const issuer = process.env.AUTH0_ISSUER_BASE_URL || '';
    const targetUrl = new URL(req.nextUrl);
    targetUrl.hostname = new URL(issuer).hostname;
    targetUrl.pathname = `/my-org${req.nextUrl.pathname}`;

    // Note: /my-org/ API requires organization context
    // For now, we don't have specific org, so we rely on user's org association
    const getAccessTokenOptions = {
      audience: `${issuer}/my-org/`,
      scope: req.headers.get('auth0-scope') || 'read:my_org:identity_providers'
      // TODO: May need to add: organization: session.user?.org_id
    };

    const fetcher = await auth0.createFetcher<Response>(undefined, {
      getAccessToken: async (options) => {
        const tokenSet = await auth0.getAccessToken({
          ...getAccessTokenOptions,
          ...options
        });
        
        // Debug: Log token details
        console.log('[DEBUG] Access token for /my-org/:', {
          token: tokenSet.token.substring(0, 50) + '...',
          tokenType: tokenSet.token_type,
          parts: tokenSet.token.split('.').length
        });
        
        // Decode payload to check for cnf claim
        try {
          const parts = tokenSet.token.split('.');
          if (parts.length === 3) {
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
            console.log('[DEBUG] Token payload - FULL:', JSON.stringify(payload, null, 2));
            console.log('[DEBUG] Token payload - CNF claim:', payload.cnf);
          } else {
            console.log('[DEBUG] Token is not a valid JWT - parts:', parts.length);
          }
        } catch (e) {
          console.log('[DEBUG] Could not decode token payload:', e.message);
        }
        
        return tokenSet.token;
      }
    });

    const response = await fetcher.fetchWithAuth(
      targetUrl.toString(),
      {
        method: req.method,
        headers: req.headers
      },
      getAccessTokenOptions
    );

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (error: any) {
    console.error('Error in /my-org/identity-providers:', error);
    return NextResponse.json(
      { error: error.message || 'Internal server error' },
      { status: 500 }
    );
  }
};

export const POST = GET;
export const PATCH = GET;
export const DELETE = GET;
