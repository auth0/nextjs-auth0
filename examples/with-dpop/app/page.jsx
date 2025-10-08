'use client';

import React from 'react';
import { useUser } from '@auth0/nextjs-auth0/client';

export default function Index() {
  const { user, isLoading } = useUser();

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
          <div className="mt-3">
            <a href="/api/shows" className="btn btn-primary">
              Test DPoP-Protected API
            </a>
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
