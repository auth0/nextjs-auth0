import React from 'react';
import { auth0 } from '../../lib/auth0';

export default async function ServerComponent() {
  let dpopApiResponse = null;
  let dpopError = null;

  try {
    // Get session for server component
    const session = await auth0.getSession();

    if (session) {
      console.info('[ServerComponent] User authenticated, making DPoP API call');

      // Use the same pattern as the API route for DPoP requests
      const relativePath = '/api/shows';

      const configuredOptions = {
        audience: process.env.AUTH0_DPOP_AUDIENCE || 'https://example.com',
        scope: process.env.AUTH0_DPOP_SCOPE || 'openid profile read:users offline_access',
        refresh: true
      };

      // Create fetcher with baseUrl configuration
      const fetcher = await auth0.createFetcher(undefined, {
        baseUrl: 'http://localhost:3001',
        getAccessToken: async function (getAccessTokenOptions) {
          console.info('[ServerComponent] Custom getAccessToken called');
          console.info(JSON.stringify(getAccessTokenOptions));
          const at = await auth0.getAccessToken(getAccessTokenOptions);
          return at.token;
        }
      });

      const response = await fetcher.fetchWithAuth(relativePath, configuredOptions);

      console.info('[ServerComponent] Response received:', response.status, response.statusText);

      if (response.ok) {
        dpopApiResponse = await response.json();
        console.info('[ServerComponent] Successful DPoP response:', dpopApiResponse);
      } else {
        const errorText = await response.text();
        dpopError = {
          error: 'API request failed',
          status: response.status,
          statusText: response.statusText,
          body: errorText
        };
        console.info('[ServerComponent] Error response:', dpopError);
      }
    } else {
      dpopError = {
        error: 'Not authenticated',
        message: 'User session not found'
      };
    }
  } catch (error) {
    console.error('[ServerComponent] Error in DPoP request:', {
      errorName: error.name,
      errorMessage: error.message,
      errorStack: error.stack?.split('\n').slice(0, 5).join('\n')
    });

    dpopError = {
      error: error.message,
      errorType: error.name,
      timestamp: new Date().toISOString()
    };
  }

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-10">
          <div className="card">
            <div className="card-header bg-info text-white">
              <h3 className="mb-0">🏗️ Server Component DPoP Example</h3>
              <small>This runs on the server during HTML generation</small>
            </div>
            <div className="card-body">
              <div className="alert alert-info">
                <strong>Server Component Context:</strong> This page is rendered on the server using Next.js Server
                Components. The DPoP API call happens during server-side rendering, and the results are included in the
                initial HTML. Note: Server Components cannot set cookies, so token refresh may not persist properly.
              </div>

              {dpopApiResponse && (
                <div className="alert alert-success">
                  <h5>✅ Server Component DPoP Success!</h5>
                  <div className="mt-3">
                    <h6>Response Data:</h6>
                    <p>
                      <strong>Message:</strong> {dpopApiResponse.msg}
                    </p>
                    <p>
                      <strong>DPoP Enabled:</strong> {dpopApiResponse.dpopEnabled ? 'Yes' : 'No'}
                    </p>
                    {dpopApiResponse.claims && (
                      <div className="mt-3">
                        <h6>Token Claims:</h6>
                        <ul className="list-unstyled">
                          <li>
                            <strong>Issuer:</strong> {dpopApiResponse.claims.iss}
                          </li>
                          <li>
                            <strong>Subject:</strong> {dpopApiResponse.claims.sub}
                          </li>
                          <li>
                            <strong>Audience:</strong>{' '}
                            {Array.isArray(dpopApiResponse.claims.aud)
                              ? dpopApiResponse.claims.aud.join(', ')
                              : dpopApiResponse.claims.aud}
                          </li>
                          <li>
                            <strong>Scope:</strong> {dpopApiResponse.claims.scope}
                          </li>
                          <li>
                            <strong>Issued At:</strong> {new Date(dpopApiResponse.claims.iat * 1000).toLocaleString()}
                          </li>
                          <li>
                            <strong>Expires At:</strong> {new Date(dpopApiResponse.claims.exp * 1000).toLocaleString()}
                          </li>
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {dpopError && (
                <div className="alert alert-danger">
                  <h5>❌ Server Component DPoP Error</h5>
                  <p>
                    <strong>Error:</strong> {dpopError.error}
                  </p>
                  {dpopError.message && (
                    <p>
                      <strong>Message:</strong> {dpopError.message}
                    </p>
                  )}
                  {dpopError.status && (
                    <p>
                      <strong>Status:</strong> {dpopError.status} {dpopError.statusText}
                    </p>
                  )}
                  {dpopError.body && (
                    <p>
                      <strong>Response:</strong> {dpopError.body}
                    </p>
                  )}
                  {dpopError.errorType && (
                    <p>
                      <strong>Type:</strong> {dpopError.errorType}
                    </p>
                  )}
                </div>
              )}

              <div className="mt-4">
                <h6>Technical Notes:</h6>
                <ul className="small text-muted">
                  <li>This request is made during server-side rendering</li>
                  <li>Results are baked into the initial HTML</li>
                  <li>No client-side JavaScript required for this data</li>
                  <li>Server Components cannot update cookies, so token refresh state may not persist</li>
                  <li>Uses the same fetchWithAuth pattern as API routes</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
