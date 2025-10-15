import { NextResponse } from 'next/server';
import { auth0 } from '../../../lib/auth0';

export const GET = async function shows() {
  try {
    const session = await auth0.getSession();
    if (!session) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    // Use relative URL with fetcher's baseUrl configuration
    const relativePath = '/api/shows';

    const configuredOptions = {
      audience: process.env.AUTH0_DPOP_AUDIENCE || 'https://example.com',
      scope: process.env.AUTH0_DPOP_SCOPE || 'openid profile read:users offline_access',
      refresh: true
    };

    const fetcher = await auth0.createFetcher<Response>(undefined, {
      baseUrl: 'http://localhost:3001',
      getAccessToken: async(getAccessTokenOptions) => {
        console.info(`[FIXED] Custom getAccessToken called with options: ${JSON.stringify(getAccessTokenOptions)}`);
        const at = await auth0.getAccessToken(getAccessTokenOptions);

        console.log(`[FIXED] auth0.getAccessToken returned: ${JSON.stringify(at)}`);
        
        // Let's decode the JWT to see the audience
        try {
          const payload = JSON.parse(Buffer.from(at.token.split('.')[1], 'base64').toString());
          console.log(`[FIXED] Decoded JWT payload - aud: ${JSON.stringify(payload.aud)}, scope: ${payload.scope}`);
          
          // Verify fix worked
          const expectedAudience = process.env.AUTH0_DPOP_AUDIENCE || 'https://example.com';
          const hasCorrectAudience = payload.aud.includes(expectedAudience);
          console.log(`[FIXED] ✅ Fix verification - Expected audience '${expectedAudience}' found in JWT: ${hasCorrectAudience}`);
          
        } catch (e: any) {
          console.log(`[FIXED] Failed to decode JWT: ${e.message}`);
        }

        return at.token;
      }
    });

    const response = await fetcher.fetchWithAuth(relativePath, configuredOptions);

    console.info('[Route] Response received:', response.status, response.statusText);

    if (!response.ok) {
      try {
        const errorText = await response.text();
        console.info('[Route] Error response body:', errorText);
        
        // Try to parse error response as JSON to preserve Auth0 configuration guidance
        let errorData;
        try {
          errorData = JSON.parse(errorText);
          console.info('[Route] Parsed error response:', errorData);
          
          // Forward the enhanced error response with Auth0 configuration guidance
          return NextResponse.json(errorData, { status: response.status });
          
        } catch (jsonParseError) {
          console.info('[Route] Error response not JSON, using text:', jsonParseError);
          
          // Fallback for non-JSON error responses
          errorData = {
            error: 'API request failed',
            status: response.status,
            statusText: response.statusText,
            body: errorText
          };
        }
        
        return NextResponse.json(errorData, { status: response.status });
        
      } catch (parseError) {
        console.info('[Route] Failed to parse error response:', parseError);
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
    console.info('[Route] Returning successful response with data:', responseData);
    return NextResponse.json(responseData);
  } catch (error) {
    console.error('[Route] Error in shows route:', {
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
