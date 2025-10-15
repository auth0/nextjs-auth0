'use client';

import React, { useState } from 'react';
import { useUser } from '@auth0/nextjs-auth0/client';

export default function ServerActionDemo() {
  const { user, isLoading } = useUser();
  const [actionResult, setActionResult] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleServerAction = async (formData) => {
    setIsSubmitting(true);
    setActionResult(null);
    setActionError(null);

    try {
      // Import the server action dynamically to avoid SSR issues
      const { testDpopServerAction } = await import('./actions');
      const result = await testDpopServerAction(formData);
      
      if (result.success) {
        setActionResult(result.data);
      } else {
        setActionError(result.error);
      }
    } catch (error) {
      setActionError({
        error: 'Server action failed',
        details: error.message
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) return <div>Loading...</div>;

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-10">
          <div className="card">
            <div className="card-header bg-success text-white">
              <h3 className="mb-0">⚡ Server Action DPoP Demo</h3>
              <small>DPoP authentication in Next.js Server Actions</small>
            </div>
            <div className="card-body">
              <div className="alert alert-success">
                <strong>Server Action Context:</strong> This demonstrates DPoP usage in Next.js Server Actions. 
                Server Actions run on the server in response to form submissions or function calls, 
                providing a secure way to handle server-side operations with DPoP authentication.
              </div>

              {user ? (
                <div className="mb-4">
                  <h5>👤 Authenticated User</h5>
                  <p><strong>Name:</strong> {user.name}</p>
                  <p><strong>Email:</strong> {user.email}</p>
                  
                  <div className="mt-4">
                    <form action={handleServerAction}>
                      <div className="mb-3">
                        <label htmlFor="testMessage" className="form-label">Test Message (optional)</label>
                        <input 
                          type="text" 
                          className="form-control" 
                          id="testMessage" 
                          name="testMessage"
                          placeholder="Enter a test message..."
                        />
                      </div>
                      
                      <button 
                        type="submit" 
                        className="btn btn-success"
                        disabled={isSubmitting}
                      >
                        {isSubmitting ? 'Running Server Action...' : 'Execute DPoP Server Action'}
                      </button>
                    </form>
                  </div>
                </div>
              ) : (
                <div className="alert alert-secondary">
                  <p>Not authenticated. <a href="/auth/login">Log in</a> to test Server Action DPoP functionality.</p>
                </div>
              )}

              {actionResult && (
                <div className="alert alert-success mt-4">
                  <h5>✅ Server Action DPoP Success!</h5>
                  <div className="mt-3">
                    <h6>Response Data:</h6>
                    <p><strong>Message:</strong> {actionResult.msg}</p>
                    <p><strong>DPoP Enabled:</strong> {actionResult.dpopEnabled ? 'Yes' : 'No'}</p>
                    <p><strong>Server Action Executed:</strong> {actionResult.serverActionExecuted ? 'Yes' : 'No'}</p>
                    {actionResult.userMessage && (
                      <p><strong>Your Message:</strong> {actionResult.userMessage}</p>
                    )}
                    {actionResult.claims && (
                      <div className="mt-3">
                        <h6>Token Claims:</h6>
                        <ul className="list-unstyled">
                          <li><strong>Issuer:</strong> {actionResult.claims.iss}</li>
                          <li><strong>Subject:</strong> {actionResult.claims.sub}</li>
                          <li><strong>Audience:</strong> {Array.isArray(actionResult.claims.aud) 
                            ? actionResult.claims.aud.join(', ') 
                            : actionResult.claims.aud}</li>
                          <li><strong>Scope:</strong> {actionResult.claims.scope}</li>
                          <li><strong>Issued At:</strong> {new Date(actionResult.claims.iat * 1000).toLocaleString()}</li>
                          <li><strong>Expires At:</strong> {new Date(actionResult.claims.exp * 1000).toLocaleString()}</li>
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {actionError && (
                <div className="alert alert-danger mt-4">
                  <h5>❌ Server Action DPoP Error</h5>
                  <p><strong>Error:</strong> {actionError.error}</p>
                  {actionError.details && <p><strong>Details:</strong> {actionError.details}</p>}
                  {actionError.status && <p><strong>Status:</strong> {actionError.status} {actionError.statusText}</p>}
                  {actionError.body && <p><strong>Response:</strong> {actionError.body}</p>}
                  {actionError.errorType && <p><strong>Type:</strong> {actionError.errorType}</p>}
                </div>
              )}

              <div className="mt-4">
                <h6>Technical Notes:</h6>
                <ul className="small text-muted">
                  <li>Server Actions run on the server in response to form submissions</li>
                  <li>Can access and modify session data securely</li>
                  <li>Support progressive enhancement (work without JavaScript)</li>
                  <li>Excellent for form handling with server-side validation</li>
                  <li>Can perform complex server-side operations with DPoP</li>
                  <li>Automatic revalidation of server components</li>
                </ul>
              </div>

              <div className="mt-4">
                <h6>Server Action Implementation:</h6>
                <pre className="bg-light p-3 rounded small">
{`// app/server-action-demo/actions.js
'use server';

import { auth0 } from '../../lib/auth0';

export async function testDpopServerAction(formData) {
  const session = await auth0.getSession();
  
  if (!session) {
    return { success: false, error: { error: 'Not authenticated' } };
  }

  const fetcher = await auth0.createFetcher(/* config */);
  const response = await fetcher.fetchWithAuth('/api/shows');
  
  if (response.ok) {
    const data = await response.json();
    return { success: true, data };
  } else {
    return { success: false, error: { error: 'API failed' } };
  }
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