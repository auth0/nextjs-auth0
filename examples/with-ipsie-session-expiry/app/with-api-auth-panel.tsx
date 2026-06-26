"use client";

import { useState } from "react";

export function WithApiAuthPanel() {
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleCall() {
    setLoading(true);
    setResult(null);
    const res = await fetch("/api/protected");
    const data = await res.json().catch(() => ({ status: res.status }));
    setResult(JSON.stringify({ status: res.status, body: data }, null, 2));
    setLoading(false);
  }

  return (
    <div>
      <p style={{ fontSize: "0.875rem", color: "#6b7280" }}>
        Calls <code>GET /api/protected</code> which is wrapped with{" "}
        <code>withApiAuthRequired()</code>. Before the ceiling it returns 200;
        after the ceiling it returns <strong>401</strong> — the guard sees a
        null session and rejects before the handler runs.
      </p>
      <button onClick={handleCall} disabled={loading}>
        {loading ? "Calling…" : "Call Protected API"}
      </button>
      {result && (
        <pre className="token" style={{ whiteSpace: "pre-wrap", marginTop: "0.75rem" }}>
          {result}
        </pre>
      )}
    </div>
  );
}
