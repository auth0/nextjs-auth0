"use client";

import { useState } from "react";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/check-domain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email })
      });

      const { isFederated, emailDomain, connection, orgId } = await res.json();

      if (isFederated) {
        const params = new URLSearchParams({
          connection,
          organization: orgId,
          login_hint: email,
          returnTo: "/dashboard"
        });

        window.location.href = `/auth/login?${params}`;
      } else {
        // Non-enterprise user — your existing login flow would go here
        setError(
          `${emailDomain} is not a federated domain. ` +
          `In a real app this would route to your existing login.`
        );
      }
    } catch (err) {
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
    </main>
  );
}
