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
      audience: 'https://dev-10whndm3tf8jetu5.us.auth0.com/api/v2/',
      scope: 'openid profile email offline_access',
      refresh: true
    };

    const fetcher = await auth0.createFetcher<Response>(undefined, {
      baseUrl: 'http://localhost:3001',
      getAccessToken: async(getAccessTokenOptions) => {
        console.info("This is a custom getAccessToken factory method")
        console.info(JSON.stringify(getAccessTokenOptions));
        const at = await auth0.getAccessToken(getAccessTokenOptions);
        return at.token;
      }
    });

    const response = await fetcher.fetchWithAuth(relativePath, configuredOptions);

    console.info('[Route] Response received:', response.status, response.statusText);

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
