"use client";

/**
 * Client component variant of the login page.
 *
 * Uses the client-side startEnterpriseLogin() exported from @auth0/nextjs-auth0.
 * It calls the SDK's mounted /auth/federated-domain route for discovery, then
 * navigates to /auth/login with login_hint. Returns a boolean so the component
 * can show loading/error state in the browser without a full page reload.
 *
 * Use this pattern when you need interactive UI feedback during the discovery
 * step. For the form POST variant see app/login/page.tsx.
 */
import { startEnterpriseLogin } from "@auth0/nextjs-auth0";
import { useState } from "react";

export default function ClientLoginPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const redirected = await startEnterpriseLogin({
        email,
        returnTo: "/dashboard"
      });

      if (!redirected) {
        // Non-enterprise user — your existing login flow would go here
        setError(
          `${email.split("@")[1] ?? email} is not a federated domain. ` +
            `In a real app this would route to your existing login.`
        );
      }
    } catch {
      setError("Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={{ maxWidth: 400, margin: "100px auto", fontFamily: "sans-serif" }}>
      <h1>Acme — Sign in</h1>
      <p style={{ color: "#666", fontSize: 14 }}>
        Enter your work email to sign in with enterprise SSO.
      </p>

      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <input
          type="email"
          placeholder="you@yourcompany.com"
          value={email}
          onChange={e => setEmail(e.target.value)}
          required
          style={{ padding: "10px 12px", fontSize: 16, border: "1px solid #ccc", borderRadius: 6 }}
        />
        <button
          type="submit"
          disabled={loading}
          style={{ padding: "10px 12px", fontSize: 16, background: "#635DFF", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer" }}
        >
          {loading ? "Checking..." : "Continue"}
        </button>
      </form>

      {error && (
        <p style={{ marginTop: 16, color: "#c00", fontSize: 14 }}>{error}</p>
      )}

      <p style={{ marginTop: 24, fontSize: 12, color: "#999" }}>
        <a href="/login" style={{ color: "#635DFF" }}>
          Back to the form POST variant
        </a>
      </p>
    </main>
  );
}
