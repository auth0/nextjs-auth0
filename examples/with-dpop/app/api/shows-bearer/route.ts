import { NextResponse } from 'next/server';
import { auth0 } from '../../../lib/auth0';

export const GET = async function showsBearer() {
  try {
    const session = await auth0.getSession();
    if (!session) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    // Use relative URL with fetcher's baseUrl configuration
    const relativePath = '/api/shows-bearer';

    const configuredOptions = {
      audience: process.env.AUTH0_BEARER_AUDIENCE || 'resource-server-1',
      scope: process.env.AUTH0_BEARER_SCOPE || 'openid profile email offline_access',
      refresh: true,
    };

    // Create fetcher with useDPoP: false to force Bearer token authentication
    const fetcher = await auth0.createFetcher<Response>(undefined, {
      baseUrl: 'http://localhost:3002',
      useDPoP: false, // Explicitly disable DPoP for this fetcher
      getAccessToken: async(getAccessTokenOptions) => {
        console.info(`[DEBUG] Bearer route getAccessToken called with options: ${JSON.stringify(getAccessTokenOptions)}`);
        const at = await auth0.getAccessToken(getAccessTokenOptions);
        
        console.log(`[DEBUG] Bearer route auth0.getAccessToken returned: ${JSON.stringify(at)}`);
        
        // Let's decode the JWT to see the audience
        try {
          const payload = JSON.parse(Buffer.from(at.token.split('.')[1], 'base64').toString());
          console.log(`[DEBUG] Bearer route decoded JWT payload - aud: ${JSON.stringify(payload.aud)}, scope: ${payload.scope}`);
        } catch (e) {
          console.log(`[DEBUG] Bearer route failed to decode JWT: ${e.message}`);
        }
        
        return at.token;
      }
    });

    const response = await fetcher.fetchWithAuth(relativePath, configuredOptions);

    console.info('[Route Bearer] Response received:', response.status, response.statusText);

    if (!response.ok) {
      try {
        const errorText = await response.text();
        console.info('[Route Bearer] Error response body:', errorText);
        return NextResponse.json(
          {
            error: 'API request failed',
            status: response.status,
            statusText: response.statusText,
            body: errorText
          },
          {
            status: response.status
          }
        );
      } catch (parseError) {
        console.info('[Route Bearer] Failed to parse error response:', parseError);
        return NextResponse.json(
          {
            error: 'API request failed with unparseable response',
            status: response.status,
            statusText: response.statusText
          },
          {
            status: response.status
          }
        );
      }
    }

    // Extract JSON data from successful response
    const responseData = await response.json();
    console.info('[Route Bearer] Returning successful response with data:', responseData);
    return NextResponse.json(responseData);
  } catch (error) {
    console.error('[Route Bearer] Error in shows-bearer route:', {
      errorName: error.name,
      errorMessage: error.message,
      errorStatus: error.status,
      errorStack: error.stack?.split('\n').slice(0, 5).join('\n')
    });

    return NextResponse.json(
      {
        error: error.message,
        errorType: error.name,
        timestamp: new Date().toISOString()
      },
      {
        status: error.status || 500
      }
    );
  }
};