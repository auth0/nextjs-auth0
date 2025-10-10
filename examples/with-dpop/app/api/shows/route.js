import { NextResponse } from 'next/server';
import { auth0 } from '../../../lib/auth0';
import { createEnhancedApiServerFetcher } from '../../../lib/fetcher';

export const GET = async function shows() {
  console.info('[Route] Shows API route called');
  console.info('[Route] Environment check:', {
    hasUseDpop: !!process.env.USE_DPOP,
    useDpopValue: process.env.USE_DPOP,
    nodeEnv: process.env.NODE_ENV,
    apiPort: process.env.API_PORT || 3001
  });

  try {
    console.info('[Route] Checking user session...');
    const session = await auth0.getSession();

    console.info('[Route] Session check result:', {
      hasSession: !!session,
      userId: session?.user?.sub || 'N/A',
      userEmail: session?.user?.email || 'N/A',
      hasTokenSet: !!session?.tokenSet,
      accessTokenLength: session?.tokenSet?.accessToken?.length || 0
    });

    if (!session) {
      console.info('[Route] No active session found - returning 401');
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    console.info('[Route] Session found, proceeding with createFetcher...');

    // Demonstrate server-side createFetcher usage
    console.info('[Route] Creating enhanced server-side fetcher...');
    const fetcher = createEnhancedApiServerFetcher();

    // Use relative URL with fetcher's baseUrl configuration
    const relativePath = '/api/shows';

    console.info('[Route] Request configuration:', {
      relativePath,
      baseUrl: `http://localhost:${process.env.API_PORT || 3001}`,
      method: 'GET',
      fetcherType: 'ServerFetcher with enhanced logging'
    });

    console.info('[Route] Making DPoP-enabled request with server-side createFetcher...');
    const response = await fetcher.fetchWithAuth(relativePath);

    console.info('[Route] Response received:', {
      status: response.status,
      statusText: response.statusText,
      hasHeaders: !!response.headers,
      contentType: response.headers.get('content-type') || 'N/A',
      responseType: typeof response
    });

    if (!response.ok) {
      console.info('[Route] Response not OK, attempting to read error response:', {
        status: response.status,
        statusText: response.statusText
      });

      try {
        const errorText = await response.text();
        console.info('[Route] Error response body:', errorText);
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

    console.info('[Route] Parsing response JSON...');
    const shows = await response.json();

    console.info('[Route] Response parsed successfully:', {
      dataType: typeof shows,
      hasMessage: !!shows.msg,
      dpopEnabled: shows.dpopEnabled,
      claimsCount: shows.claims ? Object.keys(shows.claims).length : 0,
      rawResponse: shows
    });

    console.info('[Route] Returning successful response');
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
