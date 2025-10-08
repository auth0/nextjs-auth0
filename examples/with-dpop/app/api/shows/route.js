import { NextResponse } from 'next/server';
import { auth0 } from '../../../lib/auth0';
import { createEnhancedApiServerFetcher } from '../../../lib/fetcher';

export const GET = async function shows() {
  console.log('[Route] Shows API route called');
  console.log('[Route] Environment check:', {
    hasUseDpop: !!process.env.USE_DPOP,
    useDpopValue: process.env.USE_DPOP,
    nodeEnv: process.env.NODE_ENV,
    apiPort: process.env.API_PORT || 3001
  });

  try {
    console.log('[Route] Checking user session...');
    const session = await auth0.getSession();

    console.log('[Route] Session check result:', {
      hasSession: !!session,
      userId: session?.user?.sub || 'N/A',
      userEmail: session?.user?.email || 'N/A',
      hasTokenSet: !!session?.tokenSet,
      accessTokenLength: session?.tokenSet?.accessToken?.length || 0
    });

    if (!session) {
      console.log('[Route] No active session found - returning 401');
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    console.log('[Route] Session found, proceeding with createFetcher...');

    // Demonstrate server-side createFetcher usage
    console.log('[Route] Creating enhanced server-side fetcher...');
    const fetcher = createEnhancedApiServerFetcher();

    // Use relative URL with fetcher's baseUrl configuration
    const relativePath = '/api/shows';

    console.log('[Route] Request configuration:', {
      relativePath,
      baseUrl: `http://localhost:${process.env.API_PORT || 3001}`,
      method: 'GET',
      fetcherType: 'ServerFetcher with enhanced logging'
    });

    console.log('[Route] Making DPoP-enabled request with server-side createFetcher...');
    const response = await fetcher.fetchWithAuth(relativePath);

    console.log('[Route] Response received:', {
      status: response.status,
      statusText: response.statusText,
      hasHeaders: !!response.headers,
      contentType: response.headers.get('content-type') || 'N/A',
      responseType: typeof response
    });

    if (!response.ok) {
      console.log('[Route] Response not OK, attempting to read error response:', {
        status: response.status,
        statusText: response.statusText
      });

      try {
        const errorText = await response.text();
        console.log('[Route] Error response body:', errorText);
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
        console.log('[Route] Failed to parse error response:', parseError);
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

    console.log('[Route] Parsing response JSON...');
    const shows = await response.json();

    console.log('[Route] Response parsed successfully:', {
      dataType: typeof shows,
      hasMessage: !!shows.msg,
      dpopEnabled: shows.dpopEnabled,
      claimsCount: shows.claims ? Object.keys(shows.claims).length : 0,
      rawResponse: shows
    });

    console.log('[Route] Returning successful response');
    return NextResponse.json(shows);
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
