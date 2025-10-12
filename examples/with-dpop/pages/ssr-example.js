import React from 'react';
import PropTypes from 'prop-types';

export default function SSRExample({ user, dpopApiResponse, dpopError }) {
  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-10">
          <div className="card">
            <div className="card-header bg-warning text-dark">
              <h3 className="mb-0">📄 SSR DPoP Example (getServerSideProps)</h3>
              <small>Server-side rendering with DPoP API call</small>
            </div>
            <div className="card-body">
              <div className="alert alert-warning">
                <strong>SSR Context:</strong> This page uses <code>getServerSideProps</code> to fetch data on each request. 
                The DPoP API call happens on the server before the page is rendered and sent to the browser.
                This pattern allows for dynamic, per-request data fetching with authentication.
              </div>

              {user ? (
                <div className="mb-4">
                  <h5>👤 Authenticated User</h5>
                  <p><strong>Name:</strong> {user.name}</p>
                  <p><strong>Email:</strong> {user.email}</p>
                </div>
              ) : (
                <div className="alert alert-secondary">
                  <p>Not authenticated. <a href="/auth/login">Log in</a> to see DPoP functionality.</p>
                </div>
              )}

              {dpopApiResponse && (
                <div className="alert alert-success">
                  <h5>✅ SSR DPoP Success!</h5>
                  <div className="mt-3">
                    <h6>Response Data:</h6>
                    <p><strong>Message:</strong> {dpopApiResponse.msg}</p>
                    <p><strong>DPoP Enabled:</strong> {dpopApiResponse.dpopEnabled ? 'Yes' : 'No'}</p>
                    {dpopApiResponse.claims && (
                      <div className="mt-3">
                        <h6>Token Claims:</h6>
                        <ul className="list-unstyled">
                          <li><strong>Issuer:</strong> {dpopApiResponse.claims.iss}</li>
                          <li><strong>Subject:</strong> {dpopApiResponse.claims.sub}</li>
                          <li><strong>Audience:</strong> {Array.isArray(dpopApiResponse.claims.aud) 
                            ? dpopApiResponse.claims.aud.join(', ') 
                            : dpopApiResponse.claims.aud}</li>
                          <li><strong>Scope:</strong> {dpopApiResponse.claims.scope}</li>
                          <li><strong>Issued At:</strong> {new Date(dpopApiResponse.claims.iat * 1000).toLocaleString()}</li>
                          <li><strong>Expires At:</strong> {new Date(dpopApiResponse.claims.exp * 1000).toLocaleString()}</li>
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {dpopError && (
                <div className="alert alert-danger">
                  <h5>❌ SSR DPoP Error</h5>
                  <p><strong>Error:</strong> {dpopError.error}</p>
                  {dpopError.message && <p><strong>Message:</strong> {dpopError.message}</p>}
                  {dpopError.status && <p><strong>Status:</strong> {dpopError.status} {dpopError.statusText}</p>}
                  {dpopError.body && <p><strong>Response:</strong> {dpopError.body}</p>}
                  {dpopError.errorType && <p><strong>Type:</strong> {dpopError.errorType}</p>}
                </div>
              )}

              <div className="mt-4">
                <h6>Technical Notes:</h6>
                <ul className="small text-muted">
                  <li>Data fetched on every request via <code>getServerSideProps</code></li>
                  <li>Server-side session authentication and DPoP API calls</li>
                  <li>Supports cookie-based session management</li>
                  <li>Can handle token refresh and session updates</li>
                  <li>Results are server-rendered into the initial HTML</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export async function getServerSideProps(context) {
  // Dynamic import to use auth0 in SSR context
  const { auth0 } = await import('../lib/auth0');
  
  let user = null;
  let dpopApiResponse = null;
  let dpopError = null;

  try {
    // Get session from request context
    const session = await auth0.getSession(context.req, context.res);
    
    if (session) {
      user = {
        name: session.user.name,
        email: session.user.email,
        sub: session.user.sub
      };

      console.info('[SSR] User authenticated, making DPoP API call');
      
      // Use the same pattern as the API route for DPoP requests
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
          console.info('[SSR] Custom getAccessToken called');
          console.info(JSON.stringify(getAccessTokenOptions));
          const at = await auth0.getAccessToken(context.req, context.res, getAccessTokenOptions);
          return at.token;
        }
      });

      const response = await fetcher.fetchWithAuth(relativePath, configuredOptions);
      
      console.info('[SSR] Response received:', response.status, response.statusText);

      if (response.ok) {
        dpopApiResponse = await response.json();
        console.info('[SSR] Successful DPoP response:', dpopApiResponse);
      } else {
        const errorText = await response.text();
        dpopError = {
          error: 'API request failed',
          status: response.status,
          statusText: response.statusText,
          body: errorText
        };
        console.info('[SSR] Error response:', dpopError);
      }
    } else {
      console.info('[SSR] User not authenticated');
    }
  } catch (error) {
    console.info('[SSR] Error in DPoP request:', {
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

  return {
    props: {
      user,
      dpopApiResponse,
      dpopError
    }
  };
}

SSRExample.propTypes = {
  user: PropTypes.shape({
    name: PropTypes.string,
    email: PropTypes.string,
  }),
  dpopApiResponse: PropTypes.shape({
    msg: PropTypes.string,
    dpopEnabled: PropTypes.bool,
    claims: PropTypes.shape({
      iss: PropTypes.string,
      sub: PropTypes.string,
      aud: PropTypes.oneOfType([PropTypes.string, PropTypes.arrayOf(PropTypes.string)]),
      scope: PropTypes.string,
      iat: PropTypes.number,
      exp: PropTypes.number,
    }),
  }),
  dpopError: PropTypes.shape({
    error: PropTypes.string,
    message: PropTypes.string,
    status: PropTypes.number,
    statusText: PropTypes.string,
    body: PropTypes.string,
    errorType: PropTypes.string,
  }),
};