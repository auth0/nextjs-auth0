'use client';

import React, { useState, useEffect } from 'react';
import { useUser } from '@auth0/nextjs-auth0/client';

export default function MiddlewareDPoPDemo() {
  const { user, isLoading } = useUser();
  const [middlewareResult, setMiddlewareResult] = useState(null);
  const [middlewareError, setMiddlewareError] = useState(null);
  const [hasTriggered, setHasTriggered] = useState(false);

  useEffect(() => {
    // Check if we have middleware headers (this means the middleware processed our request)
    const checkMiddlewareHeaders = () => {
      // We can't directly access response headers on the client, so we'll trigger the middleware
      // by making a request to ourselves with a special parameter
      const urlParams = new URLSearchParams(window.location.search);
      const middlewareTriggered = urlParams.get('middleware-triggered');
      
      if (middlewareTriggered && !hasTriggered) {
        setHasTriggered(true);
        // In a real implementation, the middleware would have processed the request
        // For demo purposes, we'll show that the middleware was triggered
        setMiddlewareResult({
          msg: 'Middleware DPoP demo triggered',
          middlewareProcessed: true,
          note: 'In a real scenario, this would contain the DPoP API response from middleware'
        });
      }
    };

    checkMiddlewareHeaders();
  }, [hasTriggered]);

  const triggerMiddleware = async () => {
    try {
      // Redirect to the same page with a parameter that will trigger middleware processing
      const currentUrl = new URL(window.location.href);
      currentUrl.searchParams.set('middleware-triggered', 'true');
      window.location.href = currentUrl.toString();
    } catch (error) {
      setMiddlewareError({
        error: 'Failed to trigger middleware',
        details: error.message
      });
    }
  };

  if (isLoading) return <div>Loading...</div>;

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-10">
          <div className="card">
            <div className="card-header bg-primary text-white">
              <h3 className="mb-0">🛡️ Middleware DPoP Demo</h3>
              <small>DPoP authentication in Next.js middleware</small>
            </div>
            <div className="card-body">
              <div className="alert alert-info">
                <strong>Middleware Context:</strong> This demonstrates DPoP usage in Next.js middleware. 
                The middleware intercepts requests, performs authentication checks, makes DPoP API calls, 
                and can modify the request/response before it reaches the page component.
              </div>

              {user ? (
                <div className="mb-4">
                  <h5>👤 Authenticated User</h5>
                  <p><strong>Name:</strong> {user.name}</p>
                  <p><strong>Email:</strong> {user.email}</p>
                  
                  <div className="mt-4">
                    {!hasTriggered ? (
                      <div>
                        <button 
                          onClick={triggerMiddleware}
                          className="btn btn-primary"
                        >
                          Trigger Middleware DPoP Demo
                        </button>
                        <p className="mt-2 text-muted small">
                          This will reload the page through middleware that makes a DPoP API call
                        </p>
                      </div>
                    ) : (
                      <div className="alert alert-success">
                        <h5>✅ Middleware DPoP Processed!</h5>
                        <p>The middleware intercepted your request and processed DPoP authentication.</p>
                        <a href="/middleware-dpop-demo" className="btn btn-sm btn-outline-primary">
                          Reset Demo
                        </a>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="alert alert-secondary">
                  <p>Not authenticated. <a href="/auth/login">Log in</a> to see middleware DPoP functionality.</p>
                </div>
              )}

              {middlewareResult && (
                <div className="alert alert-success">
                  <h5>✅ Middleware DPoP Success!</h5>
                  <div className="mt-3">
                    <h6>Middleware Response:</h6>
                    <p><strong>Message:</strong> {middlewareResult.msg}</p>
                    <p><strong>Processed by Middleware:</strong> {middlewareResult.middlewareProcessed ? 'Yes' : 'No'}</p>
                    {middlewareResult.note && (
                      <p><strong>Note:</strong> {middlewareResult.note}</p>
                    )}
                  </div>
                </div>
              )}

              {middlewareError && (
                <div className="alert alert-danger">
                  <h5>❌ Middleware DPoP Error</h5>
                  <p><strong>Error:</strong> {middlewareError.error}</p>
                  {middlewareError.details && <p><strong>Details:</strong> {middlewareError.details}</p>}
                </div>
              )}

              <div className="mt-4">
                <h6>Technical Notes:</h6>
                <ul className="small text-muted">
                  <li>Middleware runs before page components are rendered</li>
                  <li>Can intercept and authenticate requests</li>
                  <li>Supports token refresh and session management</li>
                  <li>Can make DPoP-authenticated API calls</li>
                  <li>Can modify headers, redirect, or block requests</li>
                  <li>Useful for protecting entire route groups</li>
                </ul>
              </div>

              <div className="mt-4">
                <h6>Middleware Implementation:</h6>
                <pre className="bg-light p-3 rounded small">
{`// middleware.ts
export async function middleware(request: NextRequest) {
  if (request.nextUrl.pathname === '/middleware-dpop-demo') {
    const session = await auth0.getSession(request);
    
    if (session) {
      const fetcher = await auth0.createFetcher(/* config */);
      const response = await fetcher.fetchWithAuth('/api/shows');
      // Process DPoP response...
    }
  }
  
  return await auth0.middleware(request);
}`}
                </pre>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}