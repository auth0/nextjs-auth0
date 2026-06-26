"use client";

import { useState } from "react";

export function UpdateSessionPanel() {
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleUpdate() {
    setLoading(true);
    setResult(null);
    const res = await fetch("/api/update-session", { method: "POST" });
    const data = await res.json();
    setResult(JSON.stringify(data, null, 2));
    setLoading(false);
  }

  return (
    <div>
      <p style={{ fontSize: "0.875rem", color: "#6b7280" }}>
        Calls a server route that runs <code>auth0.updateSession()</code>. Before
        the ceiling it succeeds; after the ceiling <code>updateSession</code>{" "}
        reads a null session and throws — the route returns a 409 with the error.
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
