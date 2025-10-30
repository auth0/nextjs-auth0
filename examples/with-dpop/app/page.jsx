'use client';

import React from 'react';
import { useUser } from '@auth0/nextjs-auth0/client';
import ServerApiCall from '../components/ServerApiCall';

export default function Index() {
  const { user, isLoading } = useUser();

  if (isLoading) return <div>Loading...</div>;

  return (
    <div className="hero my-5 text-center" data-testid="hero">
      <h1 className="mb-4" data-testid="hero-title">
        Proxy Example
      </h1>

      <p className="lead" data-testid="hero-lead">
        This example demonstrates Proxy integration with <a href="https://nextjs.org">Next.js</a> and Auth0
      </p>

      {user ? (
        <div className="mt-4" data-testid="content">
          <h3>Welcome, {user.name}!</h3>
          <p>This application demonstrates server-side Proxy for enhanced token security.</p>

          <ServerApiCall
            url="/my-org/identity-providers"
            fetchOptions={{
              headers: {
                'auth0-scope': 'read:my_org:identity_providers'
              }
            }}
            buttonLabel="Test My Organization API"
            successMessage="✅ My Organization API Test Successful!"
            failureMessage="❌ My Organization API Test Failed"
          />
        </div>
      ) : (
        <div className="mt-4">
          <p>Please log in to test Proxy functionality.</p>
          <a href="/auth/login" className="btn btn-primary">
            Log In
          </a>
        </div>
      )}
    </div>
  );
}
