"use client";

import { useState } from "react";

import { getAccessToken } from "@auth0/nextjs-auth0/client";

export function AccessTokenPanel() {
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleGetToken() {
    setLoading(true);
    setToken(null);
    setError(null);

    try {
      const t = await getAccessToken();
      setToken(t);
    } catch (err: any) {
      if (err?.code === "session_expired") {
        setError(
          "session_expired — the IdP session ceiling has been reached. The user must re-authenticate."
        );
      } else {
        setError(err?.message ?? "Failed to get access token");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <button onClick={handleGetToken} disabled={loading}>
        {loading ? "Fetching…" : "Get Access Token"}
      </button>

      {error && <div className="error">{error}</div>}

      {token && (
        <>
          <div className="label" style={{ marginTop: "0.75rem" }}>Access Token</div>
          <div className="token">{token}</div>
        </>
      )}
    </div>
  );
}
