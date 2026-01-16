"use client";

import { useUser } from "@auth0/nextjs-auth0";

export default function Home() {
  const { user, isLoading } = useUser();

  return (
    <div className="home">
      <h1>MFA Step-up Authentication Demo</h1>
      <p className="subtitle">
        Demonstrates <code>MfaRequiredError</code> handling in{" "}
        <code>@auth0/nextjs-auth0</code>
      </p>

      {isLoading ? (
        <p>Loading...</p>
      ) : user ? (
        <div className="user-section">
          <p>Logged in as <strong>{user.email}</strong></p>
          <a href="/mfa-demo" className="btn btn-primary">
            Go to MFA Demo →
          </a>
        </div>
      ) : (
        <div className="login-section">
          <p>Please log in to test the MFA step-up flow.</p>
          <a href="/auth/login" className="btn btn-primary">
            Login
          </a>
        </div>
      )}

      <div className="info-section">
        <h2>What this demo shows:</h2>
        <ul>
          <li>Calling a protected API that requires MFA step-up</li>
          <li>SDK catching Auth0's <code>mfa_required</code> error</li>
          <li>Bubbling <code>MfaRequiredError</code> with encrypted token</li>
          <li>Client handling the error and displaying MFA requirements</li>
        </ul>
      </div>
    </div>
  );
}
