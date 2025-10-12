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

    const response = await fetcher.fetchWithAuth(relativePath);

    console.info('[Route] Response received:', {
      status: response.status,
      statusText: response.statusText,
      hasHeaders: !!response.headers,
      contentType: response.headers.get('content-type') || 'N/A',
      responseType: typeof response
    });

    if (!response.ok) {
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
