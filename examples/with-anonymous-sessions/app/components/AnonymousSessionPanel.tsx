"use client";

import { useState } from "react";
import { useAnonymousSession } from "@auth0/nextjs-auth0/client";

export default function AnonymousSessionPanel() {
  const { anonymous, isLoading, error, invalidate } = useAnonymousSession();
  const [logoutError, setLogoutError] = useState<string | null>(null);

  if (isLoading) {
    return <p>Loading...</p>;
  }

  if (error) {
    return (
      <div className="error-banner">
        <strong>Error:</strong> {error.message}
      </div>
    );
  }

  if (!anonymous) {
    return <p>No anonymous session found (client-side hook).</p>;
  }

  const logout = async () => {
    setLogoutError(null);
    try {
      const response = await fetch("/auth/anonymous-session/logout", {
        method: "POST"
      });
      if (!response.ok) {
        throw new Error(`Logout failed (${response.status})`);
      }
      invalidate();
      window.location.href = "/";
    } catch (e) {
      setLogoutError(e instanceof Error ? e.message : "Logout failed");
    }
  };

  return (
    <div className="session-panel">
      <p>
        <strong>ID:</strong> {anonymous.id}
      </p>
      <p>
        <strong>Access Token (first 20 chars):</strong>{" "}
        {anonymous.accessToken.substring(0, 20)}...
      </p>
      <p>
        <strong>Expires At:</strong>{" "}
        {new Date(anonymous.expiresAt * 1000).toISOString()}
      </p>
      {anonymous.metadata && (
        <>
          <p>
            <strong>Metadata:</strong>
          </p>
          <pre>{JSON.stringify(anonymous.metadata, null, 2)}</pre>
        </>
      )}

      {logoutError && (
        <div className="error-banner">
          <strong>Error:</strong> {logoutError}
        </div>
      )}

      <div style={{ marginTop: "15px" }}>
        <button onClick={logout}>Logout</button>
        {/* Revalidates GET /auth/anonymous-session; the route renews the access token when it has expired. */}
        <button onClick={invalidate}>Refresh</button>
      </div>
    </div>
  );
}
