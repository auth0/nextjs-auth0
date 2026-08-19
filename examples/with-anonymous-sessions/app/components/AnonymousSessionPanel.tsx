"use client";

import { useAnonymousSession } from "@auth0/nextjs-auth0/client";

export default function AnonymousSessionPanel() {
  const { anonymous, isLoading, error, invalidate } = useAnonymousSession();

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
    await fetch("/auth/anonymous-session/logout", { method: "POST" });
    invalidate();
    window.location.href = "/";
  };

  const renew = async () => {
    // Trigger renewal by invalidating SWR cache and refetching
    invalidate();
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

      <div style={{ marginTop: "15px" }}>
        <button onClick={logout}>Logout</button>
        <button onClick={renew}>Renew (Force Refresh)</button>
        <button onClick={invalidate}>Invalidate Cache</button>
      </div>
    </div>
  );
}
