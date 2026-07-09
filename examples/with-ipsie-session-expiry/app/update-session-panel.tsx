"use client";

import { useState } from "react";

export function UpdateSessionPanel() {
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleUpdate() {
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/update-session", { method: "POST" });
      const data = await res.json().catch(() => ({ error: "Invalid response" }));
      setResult(JSON.stringify(data, null, 2));
    } catch (err: any) {
      setResult(JSON.stringify({ error: err.message ?? "Failed to update session" }, null, 2));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <p style={{ fontSize: "0.875rem", color: "#6b7280" }}>
        Calls a server route that runs <code>auth0.updateSession()</code>. Before
        the ceiling it succeeds; after the ceiling <code>getSession()</code>{" "}
        returns null and the route returns 401 before the update runs.
      </p>
      <button onClick={handleUpdate} disabled={loading}>
        {loading ? "Updating…" : "Update Session"}
      </button>
      {result && (
        <pre className="token" style={{ whiteSpace: "pre-wrap", marginTop: "0.75rem" }}>
          {result}
        </pre>
      )}
    </div>
  );
}
