'use client';

import React, { useState } from 'react';
import { useUser } from '@auth0/nextjs-auth0/client';
import { fetchWithAuth } from '@auth0/nextjs-auth0/client';

export default function Index() {
  const { user, isLoading } = useUser();
  const [apiResponse, setApiResponse] = useState(null);
  const [isLoadingApi, setIsLoadingApi] = useState(false);
  const [apiError, setApiError] = useState(null);
  const [clientApiResponse, setClientApiResponse] = useState(null);
  const [isLoadingClientApi, setIsLoadingClientApi] = useState(false);
  const [clientApiError, setClientApiError] = useState(null);

  const testDPopAPI = async () => {
    setIsLoadingApi(true);
    setApiError(null);
    setApiResponse(null);

    try {
      const response = await fetch('/api/shows');
      const data = await response.json();
      
      if (response.ok) {
        setApiResponse(data);
      } else {
        setApiError(data);
      }
    } catch (error) {
      setApiError({ error: 'Failed to connect to API', details: error.message });
    } finally {
      setIsLoadingApi(false);
    }
  };

  const testClientDPopAPI = async () => {
    setIsLoadingClientApi(true);
    setClientApiError(null);
    setClientApiResponse(null);

    try {
      // Use client-side fetchWithAuth directly to external API
      const apiPort = process.env.NEXT_PUBLIC_API_PORT || '3001';
      const targetUrl = `http://localhost:${apiPort}/api/shows`;
      
      const response = await fetchWithAuth(targetUrl);
      const data = await response.json();
      
      if (response.ok) {
        setClientApiResponse(data);
      } else {
        setClientApiError(data);
      }
    } catch (error) {
      setClientApiError({ error: 'Failed to connect to API via client fetchWithAuth', details: error.message });
    } finally {
      setIsLoadingClientApi(false);
    }
  };

  if (isLoading) return <div>Loading...</div>;

  return (
    <div className="hero my-5 text-center" data-testid="hero">
      <h1 className="mb-4" data-testid="hero-title">
        DPoP (Demonstration of Proof-of-Possession) Example
      </h1>

      <p className="lead" data-testid="hero-lead">
        This example demonstrates DPoP integration with <a href="https://nextjs.org">Next.js</a> and Auth0
      </p>

      {user ? (
        <div className="mt-4" data-testid="content">
          <h3>Welcome, {user.name}!</h3>
          <p>This application is configured with DPoP for enhanced token security.</p>
          
          <div className="row mt-4">
            <div className="col-md-6">
              <div className="card">
                <div className="card-header">
                  <h5 className="mb-0">Server-Side DPoP Test</h5>
                  <small className="text-muted">Via Next.js API route using auth0.fetchWithAuth()</small>
                </div>
                <div className="card-body">
                  <p>Tests DPoP through a Next.js API route that uses the server-side Auth0Client.fetchWithAuth method.</p>
                  <button 
                    onClick={testDPopAPI}
                    disabled={isLoadingApi}
                    className="btn btn-primary w-100"
                    data-testid="test-dpop-button"
                  >
                    {isLoadingApi ? 'Testing Server DPoP API...' : 'Test Server-Side DPoP API'}
                  </button>
                </div>
              </div>
            </div>
            
            <div className="col-md-6">
              <div className="card">
                <div className="card-header">
                  <h5 className="mb-0">Client-Side DPoP Test</h5>
                  <small className="text-muted">Direct client-side using fetchWithAuth()</small>
                </div>
                <div className="card-body">
                  <p>Tests DPoP directly from the browser using the client-side fetchWithAuth method.</p>
                  <button 
                    onClick={testClientDPopAPI}
                    disabled={isLoadingClientApi}
                    className="btn btn-success w-100"
                    data-testid="test-client-dpop-button"
                  >
                    {isLoadingClientApi ? 'Testing Client DPoP API...' : 'Test Client-Side DPoP API'}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* API Response Display */}
          <div className="row mt-4">
            <div className="col-md-6">
              {apiResponse && (
                <div className="p-4 bg-light border rounded" data-testid="api-response">
                  <h4 className="text-success">✅ Server-Side DPoP API Test Successful!</h4>
                  <div className="text-start">
                    <h5>Response:</h5>
                    <p><strong>Message:</strong> {apiResponse.msg}</p>
                    <p><strong>DPoP Enabled:</strong> {apiResponse.dpopEnabled ? 'Yes' : 'No'}</p>
                    {apiResponse.claims && (
                      <div>
                        <h6>Token Claims:</h6>
                        <ul className="list-unstyled">
                          <li><strong>Issuer:</strong> {apiResponse.claims.iss}</li>
                          <li><strong>Subject:</strong> {apiResponse.claims.sub}</li>
                          <li><strong>Audience:</strong> {Array.isArray(apiResponse.claims.aud) ? apiResponse.claims.aud.join(', ') : apiResponse.claims.aud}</li>
                          <li><strong>Scope:</strong> {apiResponse.claims.scope}</li>
                          <li><strong>Issued At:</strong> {new Date(apiResponse.claims.iat * 1000).toLocaleString()}</li>
                          <li><strong>Expires At:</strong> {new Date(apiResponse.claims.exp * 1000).toLocaleString()}</li>
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {apiError && (
                <div className="p-4 bg-danger text-white border rounded" data-testid="api-error">
                  <h4>❌ Server-Side DPoP API Test Failed</h4>
                  <div className="text-start">
                    <p><strong>Error:</strong> {apiError.error}</p>
                    {apiError.details && <p><strong>Details:</strong> {apiError.details}</p>}
                    {apiError.errorType && <p><strong>Type:</strong> {apiError.errorType}</p>}
                  </div>
                </div>
              )}
            </div>

            <div className="col-md-6">
              {clientApiResponse && (
                <div className="p-4 bg-light border rounded" data-testid="client-api-response">
                  <h4 className="text-success">✅ Client-Side DPoP API Test Successful!</h4>
                  <div className="text-start">
                    <h5>Response:</h5>
                    <p><strong>Message:</strong> {clientApiResponse.msg}</p>
                    <p><strong>DPoP Enabled:</strong> {clientApiResponse.dpopEnabled ? 'Yes' : 'No'}</p>
                    {clientApiResponse.claims && (
                      <div>
                        <h6>Token Claims:</h6>
                        <ul className="list-unstyled">
                          <li><strong>Issuer:</strong> {clientApiResponse.claims.iss}</li>
                          <li><strong>Subject:</strong> {clientApiResponse.claims.sub}</li>
                          <li><strong>Audience:</strong> {Array.isArray(clientApiResponse.claims.aud) ? clientApiResponse.claims.aud.join(', ') : clientApiResponse.claims.aud}</li>
                          <li><strong>Scope:</strong> {clientApiResponse.claims.scope}</li>
                          <li><strong>Issued At:</strong> {new Date(clientApiResponse.claims.iat * 1000).toLocaleString()}</li>
                          <li><strong>Expires At:</strong> {new Date(clientApiResponse.claims.exp * 1000).toLocaleString()}</li>
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {clientApiError && (
                <div className="p-4 bg-danger text-white border rounded" data-testid="client-api-error">
                  <h4>❌ Client-Side DPoP API Test Failed</h4>
                  <div className="text-start">
                    <p><strong>Error:</strong> {clientApiError.error}</p>
                    {clientApiError.details && <p><strong>Details:</strong> {clientApiError.details}</p>}
                    {clientApiError.errorType && <p><strong>Type:</strong> {clientApiError.errorType}</p>}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="mt-4">
          <p>Please log in to test DPoP functionality.</p>
          <a href="/auth/login" className="btn btn-primary">
            Log In
          </a>
        </div>
      )}
    </div>
  );
}
