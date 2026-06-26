"use client";

import { useState } from "react";

import { getAccessToken } from "@auth0/nextjs-auth0/client";

const LEEWAY = 30;

export function AccessTokenPanel({ ceiling }: { ceiling: number | null }) {
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
      // getAccessToken() throws MISSING_SESSION when getSession() returns null.
      // If the ceiling has passed, the root cause is the IPSIE ceiling — not a
      // genuinely missing session — so show a ceiling-specific message.
      const isCeilingExpired =
        err?.code === "session_expired" ||
        (err?.code === "missing_session" &&
          ceiling !== null &&
          Math.floor(Date.now() / 1000) >= ceiling - LEEWAY);

      if (isCeilingExpired) {
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
