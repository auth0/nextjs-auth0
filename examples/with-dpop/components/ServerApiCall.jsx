'use client';

import React, { useState } from 'react';

export default function ServerApiCall({
  url,
  fetchOptions = {},
  buttonLabel = 'Call API',
  successMessage = '✅ API Call Successful!',
  failureMessage = '❌ API Call Failed'
}) {
  const [isLoading, setIsLoading] = useState(false);
  const [response, setResponse] = useState(null);
  const [error, setError] = useState(null);

  const handleApiCall = async () => {
    setIsLoading(true);
    setError(null);
    setResponse(null);

    try {
      const fetchConfig = {
        ...fetchOptions,
        headers: {
          ...fetchOptions.headers
        }
      };

      const result = await fetch(url, fetchConfig);
      const data = await result.json();

      if (result.ok) {
        setResponse(data);
      } else {
        setError(data);
      }
    } catch (err) {
      setError({
        error: 'Failed to connect to API',
        details: err.message
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <div className="row mt-4 justify-content-center">
        <div className="col-md-8">
          <div className="card">
            <div className="card-header">
              <h5 className="mb-0">Server-Side Proxy Test</h5>
              <small className="text-muted">Via Next.js API route using auth0.fetchWithAuth()</small>
            </div>
            <div className="card-body">
              <p>
                Tests Proxy through a Next.js API route that uses the server-side Auth0Client.fetchWithAuth method.
              </p>
              <button
                onClick={handleApiCall}
                disabled={isLoading}
                className="btn btn-primary w-100"
                data-testid="test-Proxy-button">
                {isLoading ? `Testing Server Proxy API...` : buttonLabel}
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="row mt-4 justify-content-center">
        <div className="col-md-8">
          {response && (
            <div className="p-4 bg-light border rounded" data-testid="api-response">
              <h4 className="text-success">{successMessage}</h4>
            </div>
          )}

          {error && (
            <div className="p-4 bg-danger text-white border rounded" data-testid="api-error">
              <h4>{failureMessage}</h4>
              <div className="text-start">
                <p>
                  <strong>Error:</strong> {error.error}
                </p>
                {error.details && (
                  <p>
                    <strong>Details:</strong> {error.details.message || error.details}
                  </p>
                )}
                {error.errorType && (
                  <p>
                    <strong>Type:</strong> {error.errorType}
                  </p>
                )}

                {/* Validation Status */}
                {error.validation && (
                  <div className="mt-3 p-2 rounded col">
                    <div>Issue: {error.validation.issue}</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}