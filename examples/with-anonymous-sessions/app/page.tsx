"use client";

import { useState } from "react";
import Link from "next/link";

export default function HomePage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [metadata, setMetadata] = useState<string>(
    '{"cart_id": "cart_123", "items": 3}'
  );

  // Creates an anonymous session by POSTing to the app's own route handler,
  // which calls auth0.createAnonymousSession() and sets the encrypted
  // `auth0_anon` cookie. Pass metadata to seed set-once metadata, or omit it
  // for a plain guest session. NOTE: GET /auth/anonymous-session (the SDK
  // route) only READS the current session (200/204) — it never creates one,
  // so it cannot be used to "enter as guest".
  const createSession = async (metadataObj?: Record<string, unknown>) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/anon/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(metadataObj ? { metadata: metadataObj } : {})
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));

        // Fail-loud diagnostic for tenant misconfiguration
        if (
          res.status === 403 &&
          (body.code === "feature_not_enabled" ||
            body.code === "unauthorized_client")
        ) {
          setError(
            "Tenant not configured for anonymous sessions. Prerequisites: " +
              "(1) oidc_conformant: true on client, " +
              "(2) anonymous_sessions.active: true on client, " +
              "(3) client grant with subject_type: anonymous_user for the audience. " +
              "See TENANT-SETUP.md for details."
          );
        } else {
          setError(
            `Failed to create session: ${body.message || res.statusText}`
          );
        }
        return;
      }

      // Success: redirect to demo page
      window.location.href = "/demo";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const enterAsGuest = () => createSession();

  const createWithMetadata = () => {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(metadata);
    } catch {
      setError("Metadata is not valid JSON.");
      return;
    }
    return createSession(parsed);
  };

  return (
    <div>
      <h1>Anonymous Sessions Demo</h1>
      <p>
        This example demonstrates anonymous sessions (EA feature) in
        @auth0/nextjs-auth0. Anonymous sessions provide pre-login identity with
        1KB metadata storage.
      </p>

      <h2>Quick Start</h2>
      <p>
        <button onClick={enterAsGuest} disabled={loading}>
          {loading ? "Creating..." : "Enter as Guest"}
        </button>
        <span style={{ marginLeft: "10px", color: "#666" }}>
          Creates an anonymous session (no metadata) via POST /api/anon/create,
          then redirects to /demo
        </span>
      </p>

      <h2>Create with Metadata</h2>
      <p>
        Create an anonymous session with custom metadata (e.g., shopping cart
        state).
      </p>
      <textarea
        value={metadata}
        onChange={(e) => setMetadata(e.target.value)}
        rows={4}
        style={{ width: "100%", fontFamily: "monospace", padding: "10px" }}
        placeholder='{"cart_id": "cart_123", "items": 3}'
      />
      <button onClick={createWithMetadata} disabled={loading}>
        {loading ? "Creating..." : "Create Session"}
      </button>

      {error && (
        <div className="error-banner">
          <strong>Error:</strong> {error}
        </div>
      )}

      <h2>Login to Link</h2>
      <p>
        Already have an anonymous session?{" "}
        <Link href="/demo">Go to demo page</Link> to log in and link it to your
        account.
      </p>

      <h2>Security Notes</h2>
      <ul>
        <li>
          <strong>SEC-1 (Session Token Fixation):</strong> The SDK automatically
          injects the session_token from the cookie during login; applications
          must NOT allow session_token in authorizationParameters.
        </li>
        <li>
          <strong>Metadata Set-Once:</strong> Metadata can only be set at
          creation time, not updated after.
        </li>
        <li>
          <strong>Server Revocation:</strong> Logout clears the client cookie
          but does NOT revoke the session server-side; tokens remain valid until
          expiry.
        </li>
      </ul>
    </div>
  );
}
