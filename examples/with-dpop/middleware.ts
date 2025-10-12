import type { NextRequest } from "next/server"
import { NextResponse } from "next/server"

import { auth0 } from "./lib/auth0"

export async function middleware(request: NextRequest) {
  // Handle the special middleware DPoP demo route
  if (request.nextUrl.pathname === '/middleware-dpop-demo') {
    return await handleMiddlewareDPoPDemo(request);
  }

  // Normal Auth0 middleware processing
  return await auth0.middleware(request)
}

async function handleMiddlewareDPoPDemo(request: NextRequest) {
  console.info('[Middleware] Processing DPoP demo request');
  
  try {
    // Get session in middleware context
    const session = await auth0.getSession(request);
    
    if (!session) {
      // Redirect to login if not authenticated
      const loginUrl = new URL('/auth/login', request.url);
      loginUrl.searchParams.set('returnTo', request.nextUrl.pathname);
      return NextResponse.redirect(loginUrl);
    }

    console.info('[Middleware] User authenticated, making DPoP API call');
    
    // Create response to pass to auth0.getAccessToken for session persistence
    const response = NextResponse.next();
    
    // Use the same pattern as other examples for DPoP requests
    const relativePath = '/api/shows';
    
    const configuredOptions = {
      audience: 'https://dev-10whndm3tf8jetu5.us.auth0.com/api/v2/',
      scope: 'openid profile email offline_access',
      refresh: true
    };

    // Create fetcher with baseUrl configuration
    const fetcher = await auth0.createFetcher(undefined, {
      baseUrl: 'http://localhost:3001',
      getAccessToken: async function(getAccessTokenOptions) {
        console.log('[Middleware] Custom getAccessToken called');
        console.log(JSON.stringify(getAccessTokenOptions));
        const at = await auth0.getAccessToken(request, response, getAccessTokenOptions);
        return at.token;
      }
    });

    const apiResponse = await fetcher.fetchWithAuth(relativePath, configuredOptions);
    
    console.info('[Middleware] Response received:', apiResponse.status, apiResponse.statusText);

    let dpopResult;
    if (apiResponse.ok) {
      dpopResult = await apiResponse.json();
      console.info('[Middleware] Successful DPoP response:', dpopResult);
    } else {
      const errorText = await apiResponse.text();
      dpopResult = {
        error: 'API request failed',
        status: apiResponse.status,
        statusText: apiResponse.statusText,
        body: errorText
      };
      console.info('[Middleware] Error response:', dpopResult);
    }

    // Add custom header with DPoP result (encoded as base64 for header safety)
    const resultHeader = Buffer.from(JSON.stringify(dpopResult)).toString('base64');
    response.headers.set('X-DPoP-Result', resultHeader);
    response.headers.set('X-DPoP-Success', apiResponse.ok ? 'true' : 'false');
    
    return response;
    
  } catch (error) {
    console.error('[Middleware] Error in DPoP request:', {
      errorName: error.name,
      errorMessage: error.message,
      errorStack: error.stack?.split('\n').slice(0, 5).join('\n')
    });
    
    const dpopError = {
      error: error.message,
      errorType: error.name,
      timestamp: new Date().toISOString()
    };

    // Add error to headers
    const errorHeader = Buffer.from(JSON.stringify(dpopError)).toString('base64');
    const response = NextResponse.next();
    response.headers.set('X-DPoP-Result', errorHeader);
    response.headers.set('X-DPoP-Success', 'false');
    
    return response;
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, sitemap.xml, robots.txt (metadata files)
     */
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
}
